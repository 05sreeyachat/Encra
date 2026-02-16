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
        idleTimeout: 15000, // 15 seconds idle allowed
        mouseIdleTimeout: 10000, // 10 seconds of no mouse movement triggers idle
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
        lastMouseActivity: Date.now(), // Track mouse movement separately
        occlusionStart: null,
        verified: false,
        monitoringActive: false, // Flag to wait for camera consent
        submitting: false,      // Flag to allow legitimate form submission
        cameraAccessFailed: false, // Track failure to unblock UI
        startTime: null         // Track when camera actually started
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

    triggerDestruction: function (reason, force = false) {
        if (this.state.destroyed || (!this.state.monitoringActive && !force) || this.state.submitting) return;
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
            // Note: Keyboard activity no longer resets idle timer
            // Only mouse movement resets it (see mousemove handler below)
        });

        // 3. Mouse Blockers
        document.addEventListener('contextmenu', e => e.preventDefault());
        document.addEventListener('selectstart', e => e.preventDefault());
        document.addEventListener('mousemove', () => t.resetMouseIdle());
        document.addEventListener('mousedown', () => t.resetMouseIdle());
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
        // Check every 1s for mouse inactivity
        setInterval(() => {
            const mouseIdleTime = Date.now() - this.state.lastMouseActivity;
            if (mouseIdleTime > this.config.mouseIdleTimeout) {
                this.triggerDestruction(`Idle Timeout (No mouse movement for ${Math.round(mouseIdleTime / 1000)}s)`);
            }
        }, 1000);
    },

    resetIdle: function () {
        // Legacy method - kept for compatibility
        this.state.lastActivity = Date.now();
    },

    resetMouseIdle: function () {
        // Track mouse activity separately
        this.state.lastMouseActivity = Date.now();
    },

    initCamera: async function () {
        const t = this;
        try {
            const stream = await navigator.mediaDevices.getUserMedia({ video: { width: 320, height: 240, facingMode: 'user' } });
            t.state.cameraStream = stream;
            t.state.monitoringActive = true; // START MONITORING NOW
            t.state.startTime = Date.now();  // Mark start for grace period
            console.log("[SEC] Camera Access Granted - Monitoring ACTIVE");

            // Unlock view_decrypted.html UI if present
            const lock = document.getElementById('hardwareLock');
            if (lock) {
                lock.style.display = 'none';
                console.log('[SEC] Hardware lock removed');
            }
            const content = document.getElementById('mainContent');
            if (content) {
                content.style.filter = 'none';
                content.style.pointerEvents = 'auto';
                console.log('[SEC] Content unblurred and enabled');
            } else {
                console.warn('[SEC] mainContent element not found');
            }

            const video = document.createElement('video');
            video.srcObject = stream;
            video.play();

            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            canvas.width = 160;
            canvas.height = 120; // Low res for speed

            setInterval(() => {
                if (t.state.destroyed) return;

                // Continuous Liveness Check
                if (!stream.active || stream.getTracks().some(track => track.readyState === 'ended')) {
                    t.triggerDestruction('Camera Stream Revoked / Ended');
                    return;
                }

                ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
                const frame = ctx.getImageData(0, 0, canvas.width, canvas.height).data;

                let sum = 0;
                let sqSum = 0;
                let count = 0;
                let pixelCount = 0;

                // Sample every 4th pixel for performance
                for (let i = 0; i < frame.length; i += 4 * 4) {
                    const r = frame[i];
                    const g = frame[i + 1];
                    const b = frame[i + 2];
                    const l = 0.299 * r + 0.587 * g + 0.114 * b; // Luminance formula
                    sum += l;
                    sqSum += l * l;
                    count++;
                    pixelCount++;
                }

                const mean = sum / count;
                const variance = (sqSum / count) - (mean * mean);

                // Enhanced Heuristics for Light Detection:
                // 1. Very dark (no light) -> mean < 20
                // 2. Pitch black (completely covered) -> mean < 10
                // 3. Uniform color (covered with object) -> variance < 50
                // 4. Combined check: dark AND uniform -> high confidence of obstruction

                // Improved thresholds for better detection
                const isPitchBlack = mean < 10;  // Extremely dark
                const isVeryDark = mean < 20;    // Very low light
                const isUniform = variance < 50;  // No detail/variation

                // Blocked if: pitch black OR (very dark AND uniform)
                const isBlocked = isPitchBlack || (isVeryDark && isUniform);

                // Grace Period: 2 seconds of tolerance after camera starts
                const isGracePeriod = (Date.now() - t.state.startTime) < 2000;

                // Log detection values for debugging (every 10 checks to avoid spam)
                if (Math.random() < 0.1) {
                    console.log(`[SEC] Light Check: mean=${mean.toFixed(1)}, variance=${variance.toFixed(1)}, blocked=${isBlocked}, grace=${isGracePeriod}`);
                }

                if (isBlocked && !isGracePeriod) {
                    if (!t.state.occlusionStart) {
                        t.state.occlusionStart = Date.now();
                        console.warn(`[SEC] Darkness/Obstruction detected! mean=${mean.toFixed(1)}, variance=${variance.toFixed(1)}`);
                    }
                    const duration = Date.now() - t.state.occlusionStart;

                    // Relaxed threshold on verification page (5s vs 3s)
                    const threshold = t.config.isVerificationPage ? 5000 : t.config.occlusionThreshold;

                    if (duration > 1000 && duration < threshold) {
                        // Warn users with visual feedback
                        document.body.style.border = "5px solid red";
                        console.warn(`[SEC] Warning: Darkness detected for ${Math.round(duration / 1000)}s`);
                    }

                    if (duration > threshold) {
                        const reason = isPitchBlack
                            ? `Camera Completely Dark (mean: ${mean.toFixed(1)})`
                            : `Camera Obstructed / Environment Too Dark (mean: ${mean.toFixed(1)}, variance: ${variance.toFixed(1)})`;
                        console.error(`[SEC] TRIGGERING DESTRUCTION: ${reason}`);
                        t.triggerDestruction(reason);
                    }
                } else {
                    // Reset occlusion tracking when light is detected
                    if (t.state.occlusionStart) {
                        console.log('[SEC] Light restored, resetting occlusion timer');
                    }
                    t.state.occlusionStart = null;
                    if (!t.state.destroyed) document.body.style.border = "none";
                }

                // Update UI visualization with detailed info
                const camView = document.getElementById('camView');
                if (camView) {
                    camView.style.borderColor = isBlocked ? 'red' : 'green';
                    camView.title = `Light: ${Math.round(mean)} | Detail: ${Math.round(variance)} | ${isBlocked ? 'BLOCKED' : 'OK'}`;
                }

            }, 500); // Check every 500ms

        } catch (e) {
            console.error("[SEC] Camera Error:", e);
            t.sendAlert('camera', 'Camera Permission Denied / Error: ' + e.message);
            t.state.cameraAccessFailed = true;

            // Check if we're on the view_decrypted page (has hardwareLock element)
            const lock = document.getElementById('hardwareLock');
            const content = document.getElementById('mainContent');

            if (lock || content) {
                // On view_decrypted page: unlock content but warn user
                console.warn('[SEC] Camera failed on view page - unlocking content without monitoring');
                if (lock) lock.style.display = 'none';
                if (content) {
                    content.style.filter = 'none';
                    content.style.pointerEvents = 'auto';
                }
                // Show warning banner
                const warningBanner = document.createElement('div');
                warningBanner.style.cssText = 'position:fixed; top:20px; left:50%; transform:translateX(-50%); background:#ff6b6b; color:white; padding:15px 30px; border-radius:4px; z-index:12000; font-family:monospace; text-align:center;';
                warningBanner.innerHTML = '⚠️ Camera monitoring unavailable - Viewing without security monitoring';
                document.body.appendChild(warningBanner);
                setTimeout(() => warningBanner.remove(), 5000);
            } else {
                // On verification page or other: strict mode - destroy
                console.error('[SEC] Camera failed on non-view page - triggering destruction');
                t.triggerDestruction('Camera Failed / Not Found: ' + e.message, true);
            }
        }
    }
};
