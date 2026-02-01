/**
 * Secure File System - Client Side Monitor
 * Enforces security policies and detects threats.
 */

const SecurityMonitor = {
    // Config
    config: {
        fileId: null,      // Set by init
        destroyUrl: null,  // Set by init
        homeUrl: null,     // Set by init
        alertUrl: '/alert',
        idleTimeout: 6000, // 6 seconds idle allowed
        occlusionThreshold: 3000, // 3 seconds camera block allowed
        disableIdle: false,
        isVerificationPage: false // New: allow slightly more lenient behavior
    },

    // State
    timers: {
        idle: null,
        camera: null
    },
    state: {
        destroyed: false,
        cameraStream: null,
        lastActivity: Date.now(),
        occlusionStart: null,
        verified: false,
        monitoringActive: false, // Flag to wait for camera consent
        submitting: false,      // Flag to allow legitimate form submission
        cameraAccessFailed: false // Track failure to unblock UI
    },

    /**
     * Pre-Auth Check: Only starts camera and events. 
     * No idle timer until content is visible.
     */
    initVerification: function (fileId, destroyUrl, homeUrl) {
        this.config.fileId = fileId;
        this.config.destroyUrl = destroyUrl;
        this.config.homeUrl = homeUrl;
        this.config.isVerificationPage = true;

        console.log("[SEC] Verification Mode Initialized");
        this.bindEvents();
        // Camera started manually by user interaction to prevent "didn't ask" issues
    },

    init: function (fileId, destroyUrl, homeUrl, disableIdle = false) {
        this.config.fileId = fileId;
        this.config.destroyUrl = destroyUrl;
        this.config.homeUrl = homeUrl;
        this.config.disableIdle = disableIdle;

        console.log("[SEC] Monitor Initialized", { disableIdle });

        this.bindEvents();
        if (!disableIdle) {
            this.startIdleTimer();
        } else {
            console.log("[SEC] Idle Timer DISABLED (Long File Mode)");
        }
        this.initCamera();

        // Anti-debug
        /*
        setInterval(() => {
            if (window.outerWidth - window.innerWidth > 160 || window.outerHeight - window.innerHeight > 160) {
                this.triggerDestruction('DevTools Detected (Resize)');
            }
        }, 1000);
        */
    },

    triggerDestruction: function (reason) {
        if (this.state.destroyed || !this.state.monitoringActive || this.state.submitting) return;
        this.state.destroyed = true;

        console.warn(`[SEC] DESTROY_TRIGGER: ${reason}`);

        // Visual Warning
        document.body.style.border = "5px solid red";

        // Stop Camera
        if (this.state.cameraStream) {
            this.state.cameraStream.getTracks().forEach(track => track.stop());
        }

        // LOCKDOWN UI
        document.body.innerHTML = '<div style="background:black; color:red; height:100vh; display:flex; justify-content:center; align-items:center; text-align:center; font-family:monospace;"><h1>SECURITY LOCKDOWN<br>' + reason + '</h1></div>';

        // Notify Server
        const payload = JSON.stringify({ reason: reason });

        // Try Beacon first for reliability on unload
        if (navigator.sendBeacon) {
            navigator.sendBeacon(this.config.destroyUrl, payload);
        }

        // Also try fetch to ensure
        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
        console.log("[SEC] CSRF Token for destruction:", csrfToken);

        fetch(this.config.destroyUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: payload,
            keepalive: true
        }).finally(() => {
            setTimeout(() => window.location.replace(this.config.homeUrl), 2000);
        });
    },

    sendAlert: function (type, reason) {
        if (this.state.destroyed) return;
        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
        fetch(this.config.alertUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify({
                file_id: this.config.fileId,
                type: type,
                reason: reason
            })
        });
    },

    bindEvents: function () {
        const t = this;

        // 0. Catch Form Submission (Allow legitimate page transition)
        // Add multiple listeners to be absolutely sure
        document.addEventListener('submit', () => {
            console.log("[SEC] Form submission detected - Disabling destruction triggers");
            t.state.submitting = true;
        });

        // Also catch button clicks for forms
        document.querySelectorAll('button[type="submit"]').forEach(btn => {
            btn.addEventListener('click', () => {
                console.log("[SEC] Submit button clicked - Disabling destruction triggers");
                t.state.submitting = true;
            });
        });

        // 1. Tab Switching / Blur
        document.addEventListener('visibilitychange', () => {
            if (document.hidden && !t.config.isVerificationPage) {
                t.triggerDestruction('Tab Switch / Minimize');
            }
        });
        window.addEventListener('blur', () => {
            if (!t.config.isVerificationPage) {
                t.triggerDestruction('Window Focus Lost');
            }
        });

        // 2. Keyboard Blockers (PrintScreen, Shortcuts)
        document.addEventListener('keyup', (e) => {
            if (e.key === 'PrintScreen') {
                t.sendAlert('screenshot', 'PrintScreen Key');
                t.triggerDestruction('Screenshot Attempt');
            }
        });

        document.addEventListener('keydown', (e) => {
            // F12, Ctrl+Shift+I, Ctrl+Shift+C (DevTools)
            if (e.key === 'F12' || (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'C'))) {
                e.preventDefault();
                t.triggerDestruction('DevTools Shortcut');
            }
            // Ctrl+P (Print)
            if ((e.ctrlKey || e.metaKey) && e.key === 'p') {
                e.preventDefault();
                t.triggerDestruction('Print Attempt');
            }
            // Ctrl+S (Save)
            if ((e.ctrlKey || e.metaKey) && e.key === 's') {
                e.preventDefault();
                t.triggerDestruction('Save Attempt');
            }

            // Win+Shift+S (Snipping Tool) - Attempt to catch before focus lost
            if (e.metaKey && e.shiftKey && e.key.toLowerCase() === 's') {
                e.preventDefault(); // Likely won't stop OS, but we destroy.
                t.triggerDestruction('Snipping Tool Attempt (Win+Shift+S)');
            }

            t.resetIdle();
        });

        // 3. Mouse Blockers
        document.addEventListener('contextmenu', e => e.preventDefault());
        document.addEventListener('selectstart', e => e.preventDefault());
        document.addEventListener('mousemove', () => t.resetIdle());
        document.addEventListener('mousedown', () => t.resetIdle());
        document.addEventListener('copy', e => { e.preventDefault(); t.triggerDestruction('Clipboard Copy'); });

        // Also catch anchor clicks to prevent destruction on navigation
        document.addEventListener('click', (e) => {
            if (e.target.tagName === 'A') {
                t.state.submitting = true;
            }
        });

        // 4. Reload Prevent
        window.addEventListener('beforeunload', (e) => {
            if (!t.state.destroyed && !t.config.isVerificationPage) {
                // If native unload, just destroy.
                t.triggerDestruction('Page Reload/Unload');
            }
        });
    },

    startIdleTimer: function () {
        // Check everyday 1s
        setInterval(() => {
            if (Date.now() - this.state.lastActivity > this.config.idleTimeout) {
                this.triggerDestruction('Idle Timeout (6s)');
            }
        }, 1000);
    },

    resetIdle: function () {
        this.state.lastActivity = Date.now();
    },

    initCamera: async function () {
        const t = this;
        try {
            const stream = await navigator.mediaDevices.getUserMedia({ video: { width: 320, height: 240, facingMode: 'user' } });
            t.state.cameraStream = stream;
            t.state.monitoringActive = true; // START MONITORING NOW
            console.log("[SEC] Camera Access Granted - Monitoring ACTIVE");

            const video = document.createElement('video');
            video.srcObject = stream;
            video.play();

            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            canvas.width = 160;
            canvas.height = 120; // Low res for speed

            setInterval(() => {
                if (t.state.destroyed) return;

                ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
                const frame = ctx.getImageData(0, 0, canvas.width, canvas.height).data;

                let sum = 0;
                let sqSum = 0;
                let count = 0;

                for (let i = 0; i < frame.length; i += 4 * 4) { // sample every 4th pixel
                    const r = frame[i];
                    const g = frame[i + 1];
                    const b = frame[i + 2];
                    const l = 0.299 * r + 0.587 * g + 0.114 * b; // Luminance
                    sum += l;
                    sqSum += l * l;
                    count++;
                }

                const mean = sum / count;
                const variance = (sqSum / count) - (mean * mean);

                // Heuristics:
                // 1. Pitch black (covered completely) -> mean < 15
                // 2. Uniform color (post-it note/finger close up) -> variance < 50
                // 3. Significant sudden drop (diff check) - omitted for simplicity/stability in favor of raw thresholds

                // Tuned thresholds
                const isBlocked = (mean < 15) || (variance < 40);

                if (isBlocked) {
                    if (!t.state.occlusionStart) t.state.occlusionStart = Date.now();
                    const duration = Date.now() - t.state.occlusionStart;

                    if (duration > 1000 && duration < 3000) {
                        // Warn users? Visual feedback?
                        document.body.style.border = "5px solid red";
                    }

                    if (duration > t.config.occlusionThreshold) {
                        t.triggerDestruction('Camera Obstructed / Light Blocked');
                    }
                } else {
                    t.state.occlusionStart = null;
                    document.body.style.border = "none";
                }

                // Update UI visualization
                const camView = document.getElementById('camView');
                if (camView) {
                    camView.style.borderColor = isBlocked ? 'red' : 'green';
                    camView.title = `L: ${Math.round(mean)} V: ${Math.round(variance)}`;
                }

            }, 500); // Check every 500ms

        } catch (e) {
            console.error("Camera Error", e);
            t.sendAlert('camera', 'Camera Permission Denied / Error: ' + e.message);
            // STRICT MODE: Destroy if camera fails
            t.triggerDestruction('Camera Access Denied or Failed');
        }
    }
};
