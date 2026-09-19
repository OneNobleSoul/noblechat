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

module.exports = { isHttpUrl, sameOrigin };
