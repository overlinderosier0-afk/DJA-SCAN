# DJA-SCAN

Outil de reconnaissance WiFi/Bluetooth **passif** sur ESP32 — inspire de l'ESP32 Marauder, construit par modules.

## Materiel

- ESP32 (teste sur ESP32-D0WD-V3)
- Ecran OLED 0,96" SSD1306 (I2C 0x3C : SDA vers GPIO21, SCL vers GPIO22)
- Joystick analogique (VRX vers GPIO34, VRY vers GPIO35, SW vers GPIO32, VCC en 3,3V)

## Modules

- **Scan WiFi** : liste les reseaux (SSID, RSSI) + detail (BSSID, canal, securite)
- **Detecteur de deauth** : mode promiscuous, saut de canaux 1-13, alerte si rafale de trames de deauthentification
- **Scan BLE** : appareils Bluetooth Low Energy (nom, adresse, RSSI, TX power)
- **Sniff probes** : SSID recherches par les appareils autour (100% passif)
- **Trafic** : compteurs de trames en direct (beacons, probes, auth, deauth, data)
- **Clients** : cartographie points d'acces <-> appareils connectes

Navigation au joystick : haut/bas = defiler, clic = selectionner, gauche = retour.

## Compilation

Libs Arduino : `Adafruit GFX Library`, `Adafruit SSD1306`.
Schema de partitions : **huge_app** (le BLE est volumineux).

```bash
arduino-cli compile --fqbn esp32:esp32:esp32:PartitionScheme=huge_app dja-scan
arduino-cli upload -p /dev/ttyUSB0 --fqbn esp32:esp32:esp32:PartitionScheme=huge_app dja-scan
```

## Note

Outil 100% passif et defensif : aucune attaque, aucune emission autre que les scans standards.
