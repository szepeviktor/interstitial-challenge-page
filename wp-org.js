(() => {
    const challengeCookieName = "_hcc";
    const challengeEndpoint = "/__challenge";
    const hashPrefix = "0000";
    const maxHashAttempts = 200000000;
    const interactiveChallengeThreshold = 2;

    let challengePayload = "";
    let challengeLevel = 0;
    let interactiveToken = "";
    let requiresInteractiveChallenge = false;
    let isSubmitting = false;
    let hashcashSolution = "";
    let autoSubmitTimer = null;
    let activeCheckboxWrap = null;
    let interactiveResponse = "";

    const usedRandomIds = {};
    const byId = (id) => document.getElementById(id);

    function createElement(tagName, properties, styles) {
        const element = document.createElement(tagName);

        if (properties) {
            for (const propertyName in properties) {
                element[propertyName] = properties[propertyName];
            }
        }

        if (styles) {
            applyImportantStyles(element, styles);
        }

        return element;
    }

    async function sha256Hex(value) {
        const bytes = new TextEncoder().encode(value);
        const digest = await crypto.subtle.digest("SHA-256", bytes);

        return Array.from(new Uint8Array(digest))
            .map((byte) => byte.toString(16).padStart(2, "0"))
            .join("");
    }

    function submitChallengeIfReady() {
        if (
            isSubmitting ||
            !hashcashSolution ||
            autoSubmitTimer ||
            (requiresInteractiveChallenge && !interactiveResponse)
        ) {
            return;
        }

        isSubmitting = true;

        fetch(challengeEndpoint, {
            method: "POST",
            headers: {
                "X-Hashcash-Solution": btoa(hashcashSolution),
                "X-Interactive": interactiveResponse,
            },
        }).then((response) => {
            if (activeCheckboxWrap && response.ok) {
                activeCheckboxWrap.innerText = "Thanks, human!";
                activeCheckboxWrap.prepend(createElement("input", {
                    type: "checkbox",
                    checked: true,
                }));
            }

            window.location.reload();
        });
    }

    function uniqueRandomString(length) {
        let value;
        length = Math.max(length, 3);

        do {
            for (value = ""; value.length < length;) {
                value += Math.random().toString(36).substring(2);
            }

            value = value.substring(0, length);
        } while (usedRandomIds[value]);

        usedRandomIds[value] = true;
        return value;
    }

    function hideWithDisplayNone(element) {
        applyImportantStyles(element, {
            display: "none",
        });
    }

    function hideWithVisibilityHidden(element) {
        applyImportantStyles(element, {
            visibility: "hidden",
        });
    }

    function hideByDisablingInteraction(element) {
        applyImportantStyles(element, {
            opacity: 0,
            "pointer-events": "none",
        });

        element.querySelectorAll("input").forEach((input) => {
            input.tabOrder = -1;
        });
    }

    function randomInt(max, min) {
        min = min || 0;
        return Math.floor(Math.random() * (max - min)) + min;
    }

    function createHumanCheckbox(container, responseToken) {
        const checkboxId = uniqueRandomString(8);
        const checkboxWrap = createElement("div", {
            className: "check-wrap",
        }, {
            top: randomInt(8, 1) + "ex",
        });
        const checkbox = createElement("input", {
            type: "checkbox",
            id: checkboxId,
        });
        const label = createElement("label", {
            htmlFor: checkboxId,
            innerText: "I am human",
        });

        checkbox.addEventListener("change", () => {
            markInteractiveChallengeSelected(checkboxWrap, responseToken);
        });

        container.appendChild(checkboxWrap);
        checkboxWrap.appendChild(checkbox);
        checkboxWrap.appendChild(label);

        return checkboxWrap;
    }

    function markInteractiveChallengeSelected(checkboxWrap, responseToken) {
        activeCheckboxWrap = checkboxWrap;
        checkboxWrap.innerText = "Verifying";

        const spinner = createElement("div", {
            className: "spinner small",
        });

        checkboxWrap.prepend(spinner);

        // The server expects the selected checkbox's token in X-Interactive.
        interactiveResponse += responseToken;
        submitChallengeIfReady();
    }

    function applyImportantStyles(element, styles) {
        const stylesheet = document.styleSheets[0];
        const className = "c" + uniqueRandomString(8);
        const ruleBody = Object.keys(styles)
            .map((propertyName) => propertyName + ":" + styles[propertyName] + " !important")
            .join(";");

        element.classList.add(className);
        stylesheet.addRule("." + className, ruleBody);
    }

    function setChallengeCopy(heading, body) {
        byId("head").innerText = heading;
        byId("text").innerText = body;
    }

    function showChallengeUi() {
        if (requiresInteractiveChallenge) {
            renderInteractiveCheckboxes();
            setChallengeCopy(
                "Confirm you are human",
                "We need to check you're not a robot before you can enter this site."
            );
            byId("active").style.display = "block";
            return;
        }

        setChallengeCopy("Checking your browser", "This will only take a few seconds...");
        byId("main").appendChild(createElement("div", {
            className: "spinner big",
        }));
    }

    function renderInteractiveCheckboxes() {
        const activeContainer = byId("active");
        const realCheckboxIndex = randomInt(10);
        const hideDecoy = [hideWithDisplayNone, hideWithVisibilityHidden, hideByDisablingInteraction][randomInt(3)];

        // Render one valid checkbox and several hidden decoys with random tokens.
        for (let index = 0; index < 10; index++) {
            const isRealCheckbox = realCheckboxIndex === index;
            const responseToken = isRealCheckbox ? interactiveToken : uniqueRandomString(interactiveToken.length);
            const checkboxWrap = createHumanCheckbox(activeContainer, responseToken);

            if (isRealCheckbox) {
                applyImportantStyles(checkboxWrap, {
                    opacity: 1,
                });
            } else {
                hideDecoy(checkboxWrap);
            }
        }
    }

    function parseChallengeCookie(rawCookieValue) {
        challengePayload = atob(rawCookieValue.split(":")[1]);

        const challengeParts = challengePayload.split("|");
        challengeLevel = challengeParts[3] || 0;
        interactiveToken = challengeParts[4] || "";
        requiresInteractiveChallenge = challengeLevel >= interactiveChallengeThreshold;
    }

    function getCookie(cookieName) {
        const cookiePrefix = cookieName + "=";
        const cookies = decodeURIComponent(document.cookie).split(";");

        for (let index = 0; index < cookies.length; index++) {
            let cookie = cookies[index];

            while (cookie.charAt(0) === " ") {
                cookie = cookie.substring(1);
            }

            if (cookie.indexOf(cookiePrefix) === 0) {
                return cookie.substring(cookiePrefix.length, cookie.length);
            }
        }

        return "";
    }

    async function findHashcashSolution(requiredPrefix) {
        // The proof is the original challenge payload plus a numeric nonce.
        for (let nonce = 0; nonce < maxHashAttempts; nonce++) {
            const candidateSolution = challengePayload + nonce;
            const candidateHash = await sha256Hex(candidateSolution);

            if (candidateHash.substring(0, requiredPrefix.length) === requiredPrefix) {
                hashcashSolution = candidateSolution;
                submitChallengeIfReady();
                return;
            }
        }

        setTimeout(() => window.location.reload(), 5000);
    }

    window.addEventListener("load", () => {
        parseChallengeCookie(getCookie(challengeCookieName));

        const uiDelayMs = 10 + randomInt(100);
        window.tt = uiDelayMs;
        setTimeout(showChallengeUi, uiDelayMs);

        // Give the proof-of-work a short head start before allowing auto-submit.
        autoSubmitTimer = setTimeout(() => {
            autoSubmitTimer = null;
            submitChallengeIfReady();
        }, "3500");

        if (requiresInteractiveChallenge) {
            setTimeout(() => window.location.reload(), 120000);
        }

        findHashcashSolution(hashPrefix);
    });
})();
