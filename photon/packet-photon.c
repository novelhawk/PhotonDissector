#include "config.h"

#include <epan/packet.h>
#include <epan/wmem/wmem.h>

void proto_register_photon(void);
void proto_reg_handoff_photon(void);

static int dissect_photon(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_);
static tvbuff_t* dissect_command(proto_tree* tree, packet_info* pinfo, tvbuff_t* tvb);
static void dissect_command_headers(proto_tree* tree, packet_info* pinfo, tvbuff_t* tvb, gint32* size);
static void dissect_command_payload(proto_tree* tree, tvbuff_t* tvb, gint32 size);
static void dissect_command_join_payload(proto_tree* tree, tvbuff_t* tvb);
static tvbuff_t* dissect_packet_headers(proto_tree* tree, tvbuff_t* tvb, guint8* commands_in_packet);

// =======================
// === Wireshark stuff ===
// =======================

// Dissector proto
static int proto_photon = -1;

// Protocol trees
static int photon_tree = -1;
static int photon_header_tree = -1;
static int photon_command_tree = -1;
static int photon_command_header_tree = -1;
static int photon_command_payload_tree = -1;

// ======================
// === Packet Headers ===
// ======================

static int hf_photon_peer_id = -1;
static int hf_photon_check_crc = -1;
static int hf_photon_commands_in_packet = -1;
static int hf_photon_sent_time = -1;
static int hf_photon_challenge = -1;

// =======================
// === Command Headers ===
// =======================

static int hf_photon_command_type = -1;
static int hf_photon_command_channel_id = -1;
static int hf_photon_command_flags = -1;
static int hf_photon_command_reserved_byte = -1;
static int hf_photon_command_size = -1;
static int hf_photon_command_reliable_sequence_number = -1;

// Acknowledge
static int hf_photon_command_ack_squence_number = -1;
static int hf_photon_command_ack_sent_time = -1;

// Connect
static int hf_photon_command_mtu = -1;
static int hf_photon_command_channel_count = -1;

// VerifyConnect
static int hf_photon_command_peer_id = -1;

// Disconnect
static int hf_photon_command_disconnect_cause = -1;

// Unreliable
static int hf_photon_command_unreliable_sequence_number = -1;

// Fragmented
static int hf_photon_command_start_sequence_number = -1;
static int hf_photon_command_fragment_count = -1;
static int hf_photon_command_fragment_number = -1;
static int hf_photon_command_total_length = -1;
static int hf_photon_command_fragment_offset = -1;

// =======================
// === Command Payload ===
// =======================

static int hf_photon_command_payload_valid_udp = -1;
static int hf_photon_command_payload_encrypted = -1;
static int hf_photon_command_payload_type = -1;

// ===================================
// === Value to string assignments ===
// ===================================

static const value_string command_types[] = {
    { 0, "None" },
    { 1, "ACK" },
    { 2, "Connect" },
    { 3, "VerifyConnect" },
    { 4, "Disconnect" },
    { 5, "Ping" },
    { 6, "Reliable Command" },
    { 7, "Unreliable Command" },
    { 8, "Fragmented Command" },
    { 9, "Unsequenced Command" },
    { 10, "Configure bandwidth limit" },
    { 11, "Configure throttling" },
    { 12, "Fetch server timestamp" },
    { 0x0, NULL }
};

static const value_string payload_types[] = {
    { 0x1, "Init callbacks" },
    { 0x2, "OperationRequest" },
    { 0x3, "OperationResponse" },
    { 0x4, "EventData" },
    { 0x7, "Encryption keys exchange" },
    { 0x0, NULL }
};

static const value_string disconnects[] = {
    { 0x0, "Server" },
    { 0x1, "Server Logic" },
    { 0x2, "Timeout"},
    { 0x3, "User Limit Exceeded" },
    { 0x0, NULL }
};

static int
dissect_photon(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Photon");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item* ti = proto_tree_add_item(tree, proto_photon, tvb, 0, -1, ENC_NA);
    proto_tree* main_tree = proto_item_add_subtree(ti, photon_tree);

    guint8 commands_in_packet;
    tvb = dissect_packet_headers(main_tree, tvb, &commands_in_packet);

    col_add_fstr(pinfo->cinfo, COL_INFO, "Commands: %u; ", commands_in_packet);

    for (guint8 i = 0; i < commands_in_packet; i++)
        tvb = dissect_command(main_tree, pinfo, tvb);

    return tvb_captured_length(tvb);
}

static tvbuff_t*
dissect_packet_headers(proto_tree* tree, tvbuff_t* tvb, guint8* commands_in_packet)
{
    proto_tree* headers_tree = proto_tree_add_subtree(tree, tvb, 0, -1, photon_header_tree, NULL, "Headers");

    guint32 offset = 0;

    // Peer ID
    proto_tree_add_item(headers_tree, hf_photon_peer_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    // Check CRC
    guint8 check_crc = tvb_get_guint8(tvb, offset) == 204;
    proto_tree_add_boolean(headers_tree, hf_photon_check_crc, tvb, offset++, 1, check_crc);

    // Skip eventual CRC check
    if (check_crc)
        offset += 4;

    // Commands in packet
    *commands_in_packet = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(headers_tree, hf_photon_commands_in_packet, tvb, offset++, 1, *commands_in_packet);

    // Server Sent Time
    proto_tree_add_item(headers_tree, hf_photon_sent_time, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    // Server Challenge
    proto_tree_add_item(headers_tree, hf_photon_challenge, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_item_set_text(headers_tree, "Packet Headers: %d bytes", offset);
    proto_item_set_len(headers_tree, offset);

    return tvb_new_subset_remaining(tvb, offset);
}

static tvbuff_t*
dissect_command(proto_tree* tree, packet_info* pinfo, tvbuff_t* tvb)
{
    proto_tree* command_tree = proto_tree_add_subtree(tree, tvb, 0, -1, photon_command_tree, NULL, "Command");

    gint32 size;
    dissect_command_headers(command_tree, pinfo, tvb, &size);

    proto_item_set_text(command_tree, "Command: %d bytes", size);
    proto_item_set_len(command_tree, size);

    return tvb_new_subset_remaining(tvb, size);
}

static void
dissect_command_headers(proto_tree* tree, packet_info* pinfo, tvbuff_t* tvb, gint32* size)
{
    proto_tree* headers_tree = proto_tree_add_subtree(tree, tvb, 0, -1, photon_command_header_tree, NULL, "Headers");

    guint32 offset = 0;
    const guint8 command_type = tvb_get_guint8(tvb, offset);
    const guint8 reserved_byte = tvb_get_guint8(tvb, offset + 3);
    *size = tvb_get_gint32(tvb, offset + 4, ENC_BIG_ENDIAN);

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s; ", val_to_str(command_type, command_types, "Unknown %u"));

    proto_tree_add_uint(headers_tree, hf_photon_command_type, tvb, offset++, 1, command_type);
    proto_tree_add_item(headers_tree, hf_photon_command_channel_id, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(headers_tree, hf_photon_command_flags, tvb, offset++, 1, ENC_BIG_ENDIAN);
    proto_tree_add_uint(headers_tree, hf_photon_command_reserved_byte, tvb, offset++, 1, reserved_byte);
    proto_tree_add_int(headers_tree, hf_photon_command_size, tvb, offset, 4, *size);
    offset += 4;
    proto_tree_add_item(headers_tree, hf_photon_command_reliable_sequence_number, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    switch (command_type)
    {
    case 1: // Acknowledge
        proto_tree_add_item(headers_tree, hf_photon_command_ack_squence_number, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(headers_tree, hf_photon_command_ack_sent_time, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;

    case 2: // Join
        dissect_command_join_payload(tree, tvb_new_subset_remaining(tvb, offset));
        break;

    case 3: // VerifyConnect
        proto_tree_add_item(headers_tree, hf_photon_command_peer_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        break;

    case 6: // Reliable
        dissect_command_payload(tree, tvb_new_subset_remaining(tvb, offset), *size - offset);
        break;

    case 7: // Unreliable
        proto_tree_add_item(headers_tree, hf_photon_command_unreliable_sequence_number, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        dissect_command_payload(tree, tvb_new_subset_remaining(tvb, offset), *size - offset);
        break;

    case 8: // Fragmented
        proto_tree_add_item(headers_tree, hf_photon_command_start_sequence_number, tvb, offset + 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(headers_tree, hf_photon_command_fragment_count, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(headers_tree, hf_photon_command_fragment_number, tvb, offset + 8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(headers_tree, hf_photon_command_total_length, tvb, offset + 12, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(headers_tree, hf_photon_command_fragment_offset, tvb, offset + 16, 4, ENC_BIG_ENDIAN);
        offset += 20;

        dissect_command_payload(tree, tvb_new_subset_remaining(tvb, offset), *size - offset);
        break;
    }

    proto_item_set_text(headers_tree, "Headers: %d bytes", offset);
    proto_item_set_len(headers_tree, offset);
}

static void
dissect_command_payload(proto_tree* tree, tvbuff_t* tvb, gint32 size)
{
    proto_tree* payload_tree = proto_tree_add_subtree(tree, tvb, 0, -1, photon_command_payload_tree, NULL, "Payload");

    guint32 offset = 0;
    guint8 byte;

    byte = tvb_get_guint8(tvb, offset);
    guint8 is_valid_udp = (byte == 0xF3 || byte == 0xFD);
    proto_tree_add_boolean(payload_tree, hf_photon_command_payload_valid_udp, tvb, offset++, 1, is_valid_udp);

    byte = tvb_get_guint8(tvb, offset);
    guint8 is_encrypted = (byte & 128);
    proto_tree_add_boolean(payload_tree, hf_photon_command_payload_encrypted, tvb, offset, 1, byte);

    guint8 payload_type = (byte & 127);
    proto_tree_add_uint(payload_tree, hf_photon_command_payload_type, tvb, offset++, 1, payload_type);

    if (!is_encrypted)
    {
        //TODO: Analyze everything not game-related
        //TODO: Make subdissectors analyze the rest of the Payload
    }

    proto_item_set_text(payload_tree, "Payload: %d bytes", size);
    proto_item_set_len(payload_tree, size);
}

static void
dissect_command_join_payload(proto_tree* tree, tvbuff_t* tvb)
{
    proto_tree* payload_tree = proto_tree_add_subtree(tree, tvb, 0, 32, photon_command_payload_tree, NULL, "Payload: 32 bytes");

    proto_tree_add_item(payload_tree, hf_photon_command_mtu, tvb, 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(payload_tree, hf_photon_command_channel_count, tvb, 11, 1, ENC_BIG_ENDIAN);
}

void
proto_register_photon(void)
{
    static hf_register_info hf[] = {

        { &hf_photon_peer_id, { "Peer ID", "photon.peer_id", FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_photon_check_crc, { "Check CRC", "photon.check_crc", FT_BOOLEAN, 2, NULL, 0, NULL, HFILL } },
        { &hf_photon_commands_in_packet, { "Commands", "photon.commands_in_packet", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_photon_sent_time, { "Sent time", "photon.sent_time", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_photon_challenge, { "Challenge", "photon.challenge", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_photon_command_type, { "Type", "photon.command.type", FT_UINT8, BASE_DEC | BASE_SPECIAL_VALS, command_types, 0x0, NULL, HFILL } },
        { &hf_photon_command_channel_id, { "Channel ID", "photon.command.channel_id", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_photon_command_flags, { "Flags", "photon.command.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_photon_command_reserved_byte, { "Reserved Byte", "photon.command.reserved_byte", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_photon_command_size, { "Size", "photon.command.size", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_photon_command_reliable_sequence_number, { "Reliable Sequence Number", "photon.command.sequence_number", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        // Acknoledge
        { &hf_photon_command_ack_squence_number, { "Ack Reliable Sequence Number", "photon.command.ack_sequence_number", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_photon_command_ack_sent_time, { "Ack Sent Time", "photon.command.ack_sent_time", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        // VerifyConnect
        { &hf_photon_command_peer_id, { "Peer ID", "photon.command.peer_id", FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        // Disconnect
        { &hf_photon_command_disconnect_cause, { "Disconnect Cause", "photon.command.disconnect_cause", FT_UINT8, BASE_NONE, disconnects, 0x0, NULL, HFILL } },

        // Unreliable
        { &hf_photon_command_unreliable_sequence_number, { "Unreliable Sequence Number", "photon.command.unreliable_sequence_number", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        // Fragmented
        { &hf_photon_command_start_sequence_number, { "Start Sequence Number", "photon.command.start_sequence_number", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_photon_command_fragment_count, { "Fragments Remaining", "photon.command.fragments_remaining", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_photon_command_fragment_number, { "Fragments Number", "photon.command.fragment_number", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_photon_command_total_length, { "Total Length", "photon.command.total_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_photon_command_fragment_offset, { "Fragment Offset", "photon.command.fragmented_offset", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_photon_command_payload_valid_udp, { "Valid Operation", "photon.command.payload.valid_udp", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_photon_command_payload_encrypted, { "Encrypted", "photon.command.payload.encrypted", FT_BOOLEAN, 8, NULL, 128, NULL, HFILL } },
        { &hf_photon_command_payload_type, { "Type", "photon.command.payload.type", FT_UINT8, BASE_DEC | BASE_SPECIAL_VALS, payload_types, 127, NULL, HFILL } },

        // Payloads

        // Connect
        { &hf_photon_command_mtu, { "Peer MTU", "photon.command.mtu", FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_photon_command_channel_count, { "Channel Count", "photon.command.channel_count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    };

    static gint* ett[] = {
        &photon_tree,
        &photon_header_tree,
        &photon_command_tree,
        &photon_command_header_tree,
        &photon_command_payload_tree
    };

    proto_photon = proto_register_protocol(
        "Photon Unity Networking",
        "Photon",
        "photon"
    );

    proto_register_field_array(proto_photon, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_photon(void)
{
    static dissector_handle_t photon_handle;
    photon_handle = create_dissector_handle(dissect_photon, proto_photon);

    dissector_add_uint("udp.port", 5055, photon_handle);
    dissector_add_uint("udp.port", 5056, photon_handle);
    dissector_add_uint("udp.port", 5057, photon_handle);
    dissector_add_uint("udp.port", 5058, photon_handle);
}
