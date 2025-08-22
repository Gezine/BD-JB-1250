# BD-JB-1250
BD-JB for up to PS4 12.50  
~~This might be the exploit that was reported by TheFlow and patched at 12.52~~  
Nope TheFlow just confirmed this is not his exploit.  

Just take my early Christmas gift :)  

No this won't work at PS5.  


---

## Lapse Exploit (Firmware 9.00 – 12.02 Only)

---

### 1. Release Contents

You will find **two ISOs** in the release:

* **`Lapse.iso`** — Contains the Lapse JAR payload built in.

  * Automatically loads `payload.bin` in USB and copies it to `/data/payload.bin`.
  * BinLoader always listens to 9020 regardless of whether `payload.bin` is found or not.
* **`RemoteJarLoader.iso`** — Allows you to send your own JAR payload via port **9025**.

  * If you want the same behavior as `Lapse.iso` while using this, send **`Lapse.jar`** as the payload.

---

### 2. Preparing Your USB

* Format as **exFAT** or **FAT32**.
* Place your homebrew enabler payload (e.g. GoldHEN, ps4-hen) at the root and rename it to `payload.bin`
* For `Lapse.iso`: payload.bin will be loaded automatically.
* For `RemoteJarLoader.iso`:

  * Send a custom JAR payload, or send **Lapse.jar** to mimic `Lapse.iso`’s behavior.

---

### 3. PS4 Settings

* **Enable HDCP** in Settings (required for Blu-ray playback).
* If Blu-ray playback is **not yet activated** which can happen if you are using blue-ray disc for the first time:

  * **Disable Automatic Updates** first to avoid firmware upgrades.
  * Connect to the internet once to activate it.

---

### 4. Running the Exploit

**Step-by-step:**

1. Insert the **USB drive first**.
2. Insert the **Blu-ray disc** (burned with `Lapse.iso` or `RemoteJarLoader.iso`).
3. Wait for payload delivery:

   * With **Lapse.iso**: payload.bin loads from USB → /data/payload.bin (If USB is not plugged in)
   * With **RemoteJarLoader**: send JAR payload to port **9025**.
4. If exploit fails → **Restart the PS4** before retrying.

   * Do **not** simply reopen the BD-J app — stability will drop.

---

### 5. Logging (Optional)

* BD-J app logs are sent over network.
* Use **RemoteLogger**:

  * Server listens on port **18194**.
  * Run `log_client.py` first, then launch the BD-J app.

---

### 6. Burning the Blu-ray ISO

* **Windows**: Use **[ImgBurn](https://www.imgburn.com)**.
* **Linux**: Use **[K3b](https://apps.kde.org/k3b)**.
* **macOS**: Use **[BD-SimpleBurn](https://github.com/C4ndyF1sh/BD-SimpleBurn)**.
---

### 7. Adding AIO fixes to Lapse.iso  
The AIO fixes resolve black sreen and save data corruption issues in certain games. This is only needed for 1.00, 1.1 and 1.1b as of 1.2 the fixes are included in the ISO. 
1. Place "aiofix_USBpayload.elf" on a USB drive and name it "payload.bin". 
2. Place HEN or GoldHEN (or your desired post exploit payload) on the USB drive and name it "payload2.bin". 
You will not need the USB drive again after the initial successfull run.
---

### 8. Summary Table

| ISO Type               | What it Does              | Ports Used           | Payload Behavior                                            |
| --------------------- | ------------------------- | ------------------- | ---------------------------------------------------------- |
| Lapse.iso             | Built-in Lapse JAR payload | 9020 (if bin missing) | Loads `payload.bin` inside USB → `/data/payload.bin`         |
| RemoteJarLoader.iso   | Custom JAR payload         | 9025                  | Send `Lapse.jar` for default Lapse behavior or your own JAR |

---

### 9. Compilation Recommendation

Use **[john-tornblom's bdj-sdk](https://github.com/john-tornblom/bdj-sdk/)** for compiling.
Replace the BDJO file in `BDMV` when building.

---

### 10. Credits

* **[TheFlow](https://github.com/theofficialflow)** — BD-JB documentation & native code execution sources.
* **[hammer-83](https://github.com/hammer-83)** — PS5 Remote JAR Loader reference.
* **[john-tornblom](https://github.com/john-tornblom)** — BDJ-SDK used for compilation.
* **[shahrilnet, null\_ptr](https://github.com/shahrilnet/remote_lua_loader)** — Lua Lapse implementation, without which BD-J Lapse was impossible.

---


















