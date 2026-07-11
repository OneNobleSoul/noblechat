// NobleChat desktop shell. A thin, hardened window around the web client so
// all key generation and encryption still happen in the (Chromium) renderer,
// exactly like the browser. Point it at another deployment with NOBLECHAT_URL.
const { app, BrowserWindow, shell } = require("electron");

const APP_URL = process.env.NOBLECHAT_URL || "https://chat.noblesoul.tech/";

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

  // Open external links in the real browser, never in-app.
  win.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: "deny" };
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
