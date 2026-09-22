// NobleChat desktop shell. A thin, hardened window around the web client so
// all key generation and encryption still happen in the (Chromium) renderer,
// exactly like the browser. Point it at another deployment with NOBLECHAT_URL.
const { app, BrowserWindow, shell } = require("electron");
const { isHttpUrl, sameOrigin, permissionAllowed } = require("./url-guards.js");

const APP_URL = process.env.NOBLECHAT_URL || "https://chat.noblesoul.tech/app";

function createWindow() {
  const win = new BrowserWindow({
    width: 1200,
    height: 820,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: "#06080c",
    title: "NobleChat",
    autoHideMenuBar: true,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  // Open external links in the real browser, never in-app, and only if
  // they're actually http(s) (no handing file:/custom schemes to the shell).
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (isHttpUrl(url)) shell.openExternal(url);
    return { action: "deny" };
  });

  // The window should only ever show our own app. If the page tries to
  // navigate itself somewhere else (redirect, compromised asset, a rogue
  // window.location change), block it instead of quietly following along
  // with full app chrome still showing.
  const appOrigin = new URL(APP_URL).origin;
  win.webContents.on("will-navigate", (event, url) => {
    if (!sameOrigin(url, appOrigin)) event.preventDefault();
  });

  // Only the camera/microphone permission that calls actually need gets
  // through, and only for the app's own page - see permissionAllowed() in
  // url-guards.js. Everything else Chromium can be asked for (geolocation,
  // notifications, MIDI, HID, ...) is refused instead of silently granted.
  win.webContents.session.setPermissionRequestHandler((webContents, permission, callback, details) => {
    callback(permissionAllowed(permission, details && details.requestingUrl, appOrigin));
  });

  win.loadURL(APP_URL);
}

app.whenReady().then(() => {
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
