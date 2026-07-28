CTFd._internal.challenge.data = undefined;
CTFd._internal.challenge.renderer = null;
CTFd._internal.challenge.preRender = function () {};
CTFd._internal.challenge.render = null;
CTFd._internal.challenge.postRender = function () {};

CTFd._internal.challenge.submit = function (preview) {
    var challenge_id = parseInt(CTFd.lib.$("#challenge-id").val());
    var submission = CTFd.lib.$("#challenge-input").val();
    var body = { challenge_id: challenge_id, submission: submission };
    var params = {};
    if (preview) params["preview"] = true;
    return CTFd.api.post_challenge_attempt(params, body).then(function (response) {
        // A correct solve stops the instance server-side; resync the buttons so the player
        // isn't left with stale Extend/Terminate on a dead instance.
        if (response && response.data && response.data.status === "correct") {
            setTimeout(function () {
                if (document.getElementById("deployment-info")) view_container_info(challenge_id);
            }, 1500);
        }
        return response;
    });
};

function _csrf() {
    if (typeof init !== "undefined" && init.csrfNonce) return init.csrfNonce;
    return (window.init && window.init.csrfNonce) || "";
}

function resetAlert() {
    let alert = document.getElementById("deployment-info");
    if (!alert) return alert;
    alert.innerHTML = "";
    alert.setAttribute("aria-live", "polite");
    let spinner = document.createElement("span");
    spinner.className = "spinner-border spinner-border-sm text-primary me-2";
    spinner.setAttribute("role", "status");
    spinner.setAttribute("aria-hidden", "true");
    let status = document.createElement("span");
    status.textContent = "Starting your instance and waiting for its health check…";
    alert.append(spinner, status);
    alert.classList.remove("alert-danger");
    ["create-chal", "extend-chal", "terminate-chal"].forEach(function (id) {
        var b = document.getElementById(id); if (b) b.disabled = true;
    });
    return alert;
}

function enableButtons() {
    ["create-chal", "extend-chal", "terminate-chal"].forEach(function (id) {
        var b = document.getElementById(id); if (b) b.disabled = false;
    });
}

// Deterministic button state: running -> [Extend, Terminate]; not running -> [Fetch Instance].
// Fixes the bug where an instance that expired / was solved / errored on stop left the
// Extend/Terminate buttons showing on a dead instance.
function setContainerButtons(running) {
    var c = document.getElementById("create-chal");
    var e = document.getElementById("extend-chal");
    var t = document.getElementById("terminate-chal");
    if (c) c.classList.toggle("d-none", !!running);
    if (e) e.classList.toggle("d-none", !running);
    if (t) t.classList.toggle("d-none", !running);
}

function calculateExpiry(date) {
    return Math.max(0, Math.ceil((new Date(date * 1000) - new Date()) / 1000 / 60));
}

function createChallengeLinkElement(data, parent) {
    parent.innerHTML = "";
    let expires = document.createElement('span');
    expires.textContent = "Expires in " + calculateExpiry(new Date(data.expires)) + " minutes.";
    parent.append(expires, document.createElement('br'));
    if (data.connect == "tcp") {
        let codeElement = document.createElement('code');
        codeElement.textContent = data.endpoint || (data.hostname + ":" + data.port);
        parent.append(codeElement);
    } else {
        let link = document.createElement('a');
        link.href = data.endpoint; link.textContent = data.endpoint; link.target = '_blank';
        parent.append(link);
    }
}

// Expiry poll: while an instance is running, re-check state so the UI reverts to
// "Fetch Instance" the moment it expires, even if the modal stayed open.
var _containerPoll = null;
function _startPoll(challenge_id) {
    _stopPoll();
    _containerPoll = setInterval(function () {
        var alert = document.getElementById("deployment-info");
        if (!alert) { _stopPoll(); return; }            // modal closed
        fetch("/containers/api/view_info", {
            method: "POST",
            headers: { "Content-Type": "application/json", "Accept": "application/json", "CSRF-Token": _csrf() },
            body: JSON.stringify({ chal_id: challenge_id })
        }).then(function (r) { return r.json(); }).then(function (data) {
            if (data.status === "already_running") {
                createChallengeLinkElement(data, alert); setContainerButtons(true);
            } else {
                alert.innerHTML = data.status === "Challenge not started" ? "" : (data.message || "");
                setContainerButtons(false); _stopPoll();
            }
        }).catch(function () {});
    }, 15000);
}
function _stopPoll() { if (_containerPoll) { clearInterval(_containerPoll); _containerPoll = null; } }

function view_container_info(challenge_id) {
    let alert = resetAlert();
    fetch("/containers/api/view_info", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json", "CSRF-Token": _csrf() },
        body: JSON.stringify({ chal_id: challenge_id })
    }).then(function (r) { return r.json(); }).then(function (data) {
        alert.innerHTML = "";
        if (data.status == "already_running") {
            createChallengeLinkElement(data, alert); setContainerButtons(true); _startPoll(challenge_id);
        } else if (data.status == "Challenge not started") {
            setContainerButtons(false); _stopPoll();
        } else {
            alert.innerHTML = data.message || "Instance is not running.";
            setContainerButtons(false); _stopPoll();
        }
    }).catch(function (error) {
        alert.innerHTML = "Error fetching container info.";
        alert.classList.add("alert-danger");
        setContainerButtons(false); _stopPoll();
        console.error("Fetch error:", error);
    }).finally(enableButtons);
}

function container_request(challenge_id) {
    let alert = resetAlert();
    fetch("/containers/api/request", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json", "CSRF-Token": _csrf() },
        body: JSON.stringify({ chal_id: challenge_id })
    }).then(function (r) { return r.json(); }).then(function (data) {
        alert.innerHTML = "";
        if (data.error || data.message) {
            alert.innerHTML = data.error || data.message;
            alert.classList.add("alert-danger");
            setContainerButtons(false);
        } else {
            createChallengeLinkElement(data, alert); setContainerButtons(true); _startPoll(challenge_id);
        }
    }).catch(function (error) {
        alert.innerHTML = "Error requesting container.";
        alert.classList.add("alert-danger"); setContainerButtons(false);
        console.error("Fetch error:", error);
    }).finally(enableButtons);
}

function container_renew(challenge_id) {
    let alert = resetAlert();
    fetch("/containers/api/renew", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json", "CSRF-Token": _csrf() },
        body: JSON.stringify({ chal_id: challenge_id })
    }).then(function (r) { return r.json(); }).then(function (data) {
        alert.innerHTML = "";
        if (data.error || data.message) {
            view_container_info(challenge_id);   // renew failed (often expired) -> resync
        } else {
            createChallengeLinkElement(data, alert); setContainerButtons(true);
        }
    }).catch(function (error) {
        alert.innerHTML = "Error renewing container.";
        alert.classList.add("alert-danger"); view_container_info(challenge_id);
        console.error("Fetch error:", error);
    }).finally(enableButtons);
}

function container_stop(challenge_id) {
    let alert = resetAlert();
    fetch("/containers/api/stop", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json", "CSRF-Token": _csrf() },
        body: JSON.stringify({ chal_id: challenge_id })
    }).then(function (r) { return r.json(); }).then(function (data) {
        // Whether it stopped cleanly or was already gone, the instance is not running now.
        alert.innerHTML = (data.error || data.message) ? (data.error || data.message) : "Instance terminated.";
        setContainerButtons(false); _stopPoll();
    }).catch(function (error) {
        alert.innerHTML = "Instance terminated.";
        setContainerButtons(false); _stopPoll();
        console.error("Fetch error:", error);
    }).finally(enableButtons);
}
