m = {}

function m.create_dissector() 
    -- SSH field used
    ssh_encrypted_data = Field.new("ssh.encrypted_packet")
    --ssh_encrypted_len = Field.new("ssh.encrypted_len")
    packet_number = Field.new("frame.number")
    direction = Field.new("ssh.direction")
    packet_length = Field.new("ssh.packet_length")
    ssh_padding_length = Field.new("ssh.padding_length")
    --encrypted_packet_length = Field.new("ssh.encrypted_packet_length")


    -- New protocol definition
    ssh_decrypt = Proto("SSH_Payload", "SSH Decrypted Payload")
    ssh_auth = Proto("SSHAuthenticationProtocol", "SSH Authentication Protocol")
    ssh_connection = Proto("SSHConnectionProtocol", "SSH Connection Protocol")
    ssh_transport = Proto("SSHTransportProtocol", "SSH Transport Protocol")
    -- fields


    message_type_field = ProtoField.string("SSH.message_type_decrypted","Message Type")
    decrypted_data_field = ProtoField.string("SSH.decrypted_data","Decrypted Data")
    padding_length_field = ProtoField.string("SSH.padding_length_decrypted","Padding Length")
    padding_field = ProtoField.string("SSH.padding","Padding")
    service_name_field = ProtoField.string("SSH.service_name","Service Name")
    user_name_field = ProtoField.string("SSH.user_name","User Name")
    password_field = ProtoField.string("SSH.password","Password")
    auth_method_field = ProtoField.string("SSH.auth_method","Auth Method")
    publick_key_blob_field = ProtoField.string("SSH.publick_key_blob","Public Key Blob")
    signature_field = ProtoField.string("SSH.signature","Signature")
    reason_code_field = ProtoField.string("SSH.reason_code","Reason Code")
    reason_string_field = ProtoField.string("SSH.reason_string","Reason String")
    language_tag_field = ProtoField.string("SSH.language_tag","Language Tag")
    public_key_alg_field = ProtoField.string("SSH.public_key_alg","Public Key Alg")
    public_key_field = ProtoField.string("SSH.public_key","Public Key")
    boolean_public_key_field = ProtoField.string("SSH.boolean_public_key","Authentication request") -- ?
    auth_that_can_continue_field = ProtoField.string("SSH.auth_that_can_continue","Auth That Can Continue")
    seq_no_field = ProtoField.string("SSH.seq_no","Seq No")
    display_field = ProtoField.string("SSH.display","Display")
    channel_type_field = ProtoField.string("SSH.channel_type","Channel Type")
    channel_number_field = ProtoField.string("SSH.channel_number","Channel Number")
    window_size_field = ProtoField.string("SSH.window_size","Window Size")
    max_packet_size_field = ProtoField.string("SSH.max_packet_size","Max Packet Size")
    originator_address_field = ProtoField.string("SSH.originator_address","Originator Address")
    originator_port_field = ProtoField.string("SSH.originator_port","Originator Port")
    recipient_address_field = ProtoField.string("SSH.recipient_address","Recipient Address")
    recipient_port_field = ProtoField.string("SSH.recipient_port","Recipient Port")
    recipient_channel_number_field = ProtoField.string("SSH.recipient_channel_number","Recipient Channel Number")
    description_field = ProtoField.string("SSH.description","Description")
    bytes_to_add_field = ProtoField.string("SSH.bytes_to_add","Bytes To Add")
    data_field = ProtoField.string("SSH.data","Data")
    partial_success_field = ProtoField.string("SSH.partial_success","Partial Success")
    host_name_field = ProtoField.string("SSH.host_name","Host Name")
    data_type_code_field = ProtoField.string("SSH.data_type_code","Data Type Code")
    request_type_field = ProtoField.string("SSH.request_type","Request Type")
    want_reply_field = ProtoField.string("SSH.want_reply","Want Reply")
    terminal_mode_field = ProtoField.string("SSH.terminal_mode","Terminal Mode")
    terminal_width_characters_field = ProtoField.string("SSH.terminal_width_characters","Terminal Width Characters")
    terminal_height_rows_field = ProtoField.string("SSH.terminal_height_rows","Terminal Height Rows")
    terminal_width_pixels_field = ProtoField.string("SSH.terminal_width_pixels","Terminal Width Pixels")
    terminal_height_pixels_field = ProtoField.string("SSH.terminal_height_pixels","Terminal Height Pixels")
    terminal_modes_field = ProtoField.string("SSH.terminal_modes","Terminal Modes")
    single_connection_field = ProtoField.string("SSH.single_connection","Single Connection")
    x11_authentication_protocol_field = ProtoField.string("SSH.x11_authentication_protocol","X11 Authentication Protocol")
    x11_authentication_cookie_field = ProtoField.string("SSH.x11_authentication_cookie","X11 Authentication Cookie")
    x11_screen_number_field = ProtoField.string("SSH.x11_screen_number","X11 Screen Number")
    variable_name_field = ProtoField.string("SSH.variable_name","Variable Name")
    subsystem_name_field = ProtoField.string("SSH.subsystem_name","Subsystem Name")
    command_field = ProtoField.string("SSH.command","Command")
    terminal_width_characters_field = ProtoField.string("SSH.terminal_width_characters","Terminal Width Characters")
    terminal_height_rows_field = ProtoField.string("SSH.terminal_height_rows","Terminal Height Rows")
    terminal_width_pixels_field = ProtoField.string("SSH.terminal_width_pixels","Terminal Width Pixels")
    terminal_height_pixels_field = ProtoField.string("SSH.terminal_height_pixels","Terminal Height Pixels")
    client_can_do_field = ProtoField.string("SSH.client_can_do","Client Can Do")
    signal_name_field = ProtoField.string("SSH.signal_name","Signal Name")
    exit_status_field = ProtoField.string("SSH.exit_status","Exit Status")
    core_dumped_field = ProtoField.string("SSH.core_dumped","Core Dumped")
    error_message_field = ProtoField.string("SSH.error_message","Error Message")
    language_tag_field = ProtoField.string("SSH.language_tag","Language Tag")
    encoded_terminal_modes_field = ProtoField.string("SSH.encoded_terminal_modes","Encoded Terminal Modes")
    message_field = ProtoField.string("SSH.message","Message")
    ext_type_field = ProtoField.string("SSH.ext_type","Ext Type")
    ext_data_field = ProtoField.string("SSH.ext_data","Ext Data")
    address_to_bind_field = ProtoField.string("SSH.address_to_bind","Address To Bind")
    port_to_bind_field = ProtoField.string("SSH.port_to_bind","Port To Bind")

    ssh_decrypt.fields = {
        message_type_field,decrypted_data_field,padding_length_field,
        padding_field,service_name_field,user_name_field,password_field,
        auth_method_field,publick_key_blob_field,signature_field,
        reason_code_field,reason_string_field,language_tag_field,
        public_key_alg_field, partial_success_field, public_key_field, boolean_public_key_field,
        channel_type_field, channel_number_field, window_size_field,
        max_packet_size_field, host_name_field, auth_that_can_continue_field,  originator_address_field, originator_port_field,
        recipient_address_field, recipient_port_field, recipient_channel_number_field,
        description_field, bytes_to_add_field, data_field, data_type_code_field,
        request_type_field, want_reply_field, terminal_mode_field,
        terminal_width_characters_field, terminal_height_rows_field,
        terminal_width_pixels_field, terminal_height_pixels_field,
        terminal_modes_field, single_connection_field,
        x11_authentication_protocol_field, x11_authentication_cookie_field,
        x11_screen_number_field, variable_name_field, subsystem_name_field,
        command_field, client_can_do_field, signal_name_field, exit_status_field,
        core_dumped_field, error_message_field, seq_no_field, message_field, display_field,
        ext_type_field, ext_data_field, address_to_bind_field, port_to_bind_field
    }

    -- Preferences

    p = ssh_decrypt.prefs
    p.ck = Pref.string("Client key", "", "")
    p.sk = Pref.string("Server key", "", "")
    p.civ = Pref.string("Client IV", "", "")
    p.siv = Pref.string("Server IV", "", "")

    encryption_table = {
        {1, "aes-128-cbc", 1},
        {2, "aes-128-ctr", 2},
        {3, "3des-cbc", 3}
    }

    p.encryption_alg = Pref.enum(
        "Encryption algorithm", 1 , "", encryption_table, false
    )

    p.enable = Pref.bool( "Decryption enabled?", false, "" )
end

return m