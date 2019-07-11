# Photon Dissector

Photon Unity Networking (PUN) is a Unity package that handles the networking of multiplayer games.

## Milestones

- [x] Bind the dissector to Photon's packets
- [x] Dissect the packet headers
- [x] For every command contained in the packet dissect:
    - [x] The Command's Header
    - [ ] The Command's Payload
- [ ] Delegate dissection of game-specific data to sub-dissectors
