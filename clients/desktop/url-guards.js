// Pure URL checks for the desktop shell's navigation guards. Kept dependency
// free (no "electron" import) so they can run under plain node --test.

function isHttpUrl(url) {
  try {
    return /^https?:$/.test(new URL(url).protocol);
  } catch {
    return false;
  }
}

function sameOrigin(url, origin) {
  try {
    return new URL(url).origin === origin;
  } catch {
    return false;
  }
}

// Electron auto-approves every permission request (camera, mic, geolocation,
// notifications, MIDI, HID, USB, ...) unless the app supplies a handler that
// says otherwise. NobleChat only ever needs "media" (camera/microphone, for
// voice/video calls), and only for its own page - everything else, and any
// request from a page that isn't the app itself, gets refused.
const ALLOWED_PERMISSIONS = new Set(["media"]);

function permissionAllowed(permission, requestingUrl, appOrigin) {
  return ALLOWED_PERMISSIONS.has(permission) && sameOrigin(requestingUrl, appOrigin);
}

module.exports = { isHttpUrl, sameOrigin, permissionAllowed };
