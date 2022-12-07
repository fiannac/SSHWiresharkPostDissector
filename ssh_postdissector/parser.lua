m = {}
local codes = require("codes")
local utils = require("utils")

function parse_transport_protocol(packet, subtree, message_type_string)
    if(message_type_string == "SSH_MSG_DISCONNECT") then
        local reason_code = packet:sub(5,12)
        reason_code = tonumber(reason_code, 16)
        reason_code = codes.reason_codes[reason_code]
        local base = 12 + 1
        local description_length = packet:sub(base,base + 7)
        description_length = tonumber(description_length, 16)
        local description = packet:sub(base + 8,base + 7 + description_length*2)
        description = utils.hexdecode(description)
        base = base + 7 + description_length*2 + 1
        local language_tag_length = packet:sub(base,base + 7)
        language_tag_length = tonumber(language_tag_length, 16)
        local language_tag = packet:sub(base + 8,base + 7 + language_tag_length*2)
        language_tag = utils.hexdecode(language_tag)
        
        subtree:add(reason_code_field, reason_code)
        subtree:add(reason_string_field, description)
        subtree:add(language_tag_field, language_tag)
    end

    if(message_type_string == "SSH_MSG_IGNORE") then
        local data_length = packet:sub(5,12)
        data_length = tonumber(data_length, 16)
        local data = packet:sub(13,12 + data_length*2)
        data = utils.hexdecode(data)
        subtree:add(data_field, data)
    end	

    if(message_type_string == "SSH_MSG_UNIMPLEMENTED") then
        local seq_no = packet:sub(5,12)
        seq_no = tonumber(seq_no, 16)
        subtree:add(seq_no_field, seq_no)
    end

    if(message_type_string == "SSH_MSG_DEBUG") then
        local display = packet:sub(5,6)
        display = tonumber(display, 16)
        if(display == 0) then display = "false" 
        else display = "true" end
        local base = 6 + 1
        local message_length = packet:sub(base,base + 7)
        message_length = tonumber(message_length, 16)
        local message = packet:sub(base + 8,base + 7 + message_length*2)
        message = utils.hexdecode(message)
        base = base + 7 + message_length*2 + 1
        local language_tag_length = packet:sub(base,base + 7)
        language_tag_length = tonumber(language_tag_length, 16)
        local language_tag = packet:sub(base + 8,base + 7 + language_tag_length*2)
        language_tag = utils.hexdecode(language_tag)
        
        subtree:add(display_field, display)
        subtree:add(message_field, message)
        subtree:add(language_tag_field, language_tag)
    end

    if(message_type_string == "SSH_MSG_SERVICE_REQUEST") then
        local service_name_length = packet:sub(5,12)
        service_name_length = tonumber(service_name_length, 16)
        local service_name = packet:sub(13,12 + service_name_length*2)
        service_name = utils.hexdecode(service_name)
        subtree:add(service_name_field, service_name)
    end

    if(message_type_string == "SSH_MSG_SERVICE_ACCEPT") then
        local service_name_length = packet:sub(5,12)
        service_name_length = tonumber(service_name_length, 16)
        local service_name = packet:sub(13,12 + service_name_length*2)
        service_name = utils.hexdecode(service_name)
        subtree:add(service_name_field, service_name)
    end

    if(message_type_string == "SSH_MSG_EXT_INFO") then 
        local num_ext = packet:sub(5,12)
        num_ext = tonumber(num_ext, 16)
        local base = 12 + 1
        for i=1,num_ext do
            local ext_type_len = packet:sub(base,base + 7)
            ext_type_len = tonumber(ext_type_len, 16)
            local ext_type = packet:sub(base + 8,base + 7 + ext_type_len*2)
            ext_type = utils.hexdecode(ext_type)
            base = base + 8 + ext_type_len*2
            local ext_data_length = packet:sub(base,base + 7)
            ext_data_length = tonumber(ext_data_length, 16)
            local ext_data = packet:sub(base + 8,base + 7 + ext_data_length*2)
            ext_data = utils.hexdecode(ext_data)
            base = base + 8 + ext_data_length*2
            subtree:add(ext_type_field, ext_type)
            subtree:add(ext_data_field, ext_data)
        end
    end
end

function parse_auth_protocol(packet, subtree, message_type_string)
    
    if(message_type_string == "SSH_MSG_USERAUTH_REQUEST") then
        local user_name_length = packet:sub(5,12)
        user_name_length = tonumber(user_name_length, 16)
        local user_name = packet:sub(13,12 + user_name_length*2)
        user_name = utils.hexdecode(user_name)
        subtree:add(user_name_field, user_name)
        local base = 12 + user_name_length*2 + 1
        local service_name_length = packet:sub(base,base+7)
        service_name_length = tonumber(service_name_length, 16)
        local service_name = packet:sub(base+8,base + 7 + service_name_length*2)
        service_name = utils.hexdecode(service_name)
        subtree:add(service_name_field, service_name)
        base = base + 7 + service_name_length*2 + 1
        local method_name_length = packet:sub(base,base+7)
        method_name_length = tonumber(method_name_length, 16)
        local method_name = packet:sub(base+8,base+7+method_name_length*2)
        method_name = utils.hexdecode(method_name)
        subtree:add(auth_method_field, method_name)
        base = base + 7 + method_name_length*2 + 1

        if(method_name == "none") then
            return
        elseif(method_name == "password") then
            local change_password = packet:sub(base,base+1)
            change_password = tonumber(change_password, 16)
            base = base + 2
            local password_length = packet:sub(base, base + 7)
            password_length = tonumber(password_length, 16)
            local password = packet:sub(base + 8,base + 7 + password_length*2)
            password = utils.hexdecode(password)
            subtree:add(password_field, password)
            base = base + 7 + password_length*2 + 1
            if(change_password == 1) then
                local new_password_length = packet:sub(base, base + 7)
                new_password_length = tonumber(new_password_length, 16)
                local new_password = packet:sub(base + 8,base + 7 + new_password_length*2)
                new_password = utils.hexdecode(new_password)
                subtree:add(new_password_field, new_password)
            end

        elseif(method_name == "publickey") then 
            local boolean = packet:sub(base,base + 1)
            boolean = tonumber(boolean, 16)
            base = base + 2
            if(boolean == 0) then
                subtree:add(boolean_public_key_field, "false")
                local public_key_alg_length = packet:sub(base,base + 7)
                public_key_alg_length = tonumber(public_key_alg_length, 16)
                local public_key_alg = packet:sub(base + 8,base + 7 + public_key_alg_length*2)
                public_key_alg = utils.hexdecode(public_key_alg)
                subtree:add(public_key_alg_field, public_key_alg)
                base = base + 7 + public_key_alg_length*2 + 1
                local public_key_length = packet:sub(base,base + 7)
                public_key_length = tonumber(public_key_length, 16)
                local public_key_blob = packet:sub(base + 8, base + 7 + public_key_length*2)
                subtree:add(publick_key_blob_field, public_key_blob)
            else 
                subtree:add(boolean_public_key_field, "true")
                local public_key_alg_length = packet:sub(base,base + 7)
                public_key_alg_length = tonumber(public_key_alg_length, 16)
                local public_key_alg = packet:sub(base + 8,base + 7 + public_key_alg_length*2)
                public_key_alg = utils.hexdecode(public_key_alg)
                subtree:add(public_key_alg_field, public_key_alg)
                base = base + 7 + public_key_alg_length*2 + 1
                local public_key_length = packet:sub(base,base+7)
                public_key_length = tonumber(public_key_length, 16)
                local public_key = packet:sub(base + 8,base + 7 + public_key_length*2)
                subtree:add(public_key_field, public_key)
                base = base+7+public_key_length*2+1
                local signature_length = packet:sub(base,base+7)
                signature_length = tonumber(signature_length, 16)
                local signature = packet:sub(base+8,base+7+signature_length*2)
                subtree:add(signature_field, signature)
            end

        elseif(method_name == "hostbased") then
            local public_key_alg_length = packet:sub(base,base + 7)
            public_key_alg_length = tonumber(public_key_alg_length, 16)
            local public_key_alg = packet:sub(base + 8,base + 7 + public_key_alg_length*2)
            public_key_alg = utils.hexdecode(public_key_alg)
            subtree:add(public_key_alg_field, public_key_alg)
            base = base + 7 + public_key_alg_length*2 + 1
            local public_key_length = packet:sub(base,base + 7)
            public_key_length = tonumber(public_key_length, 16)
            local public_key = packet:sub(base + 8,base + 7 + public_key_length*2)
            public_key = utils.hexdecode(public_key)
            subtree:add(public_key_field, public_key)
            base = base + 7 + public_key_length*2 + 1
            local host_name_length = packet:sub(base,base + 7)
            host_name_length = tonumber(host_name_length, 16)
            local host_name = packet:sub(base + 8,base + 7 + host_name_length*2)
            host_name = utils.hexdecode(host_name)
            subtree:add(host_name_field, host_name)
            base = base + 7 + host_name_length*2 + 1
            local user_name_length = packet:sub(base,base + 7)
            user_name_length = tonumber(user_name_length, 16)
            local user_name = packet:sub(base + 8,base + 7 + user_name_length*2)
            user_name = utils.hexdecode(user_name)
            subtree:add(user_name_field, user_name)
            base = base + 7 + user_name_length*2 + 1
            local signature_length = packet:sub(base,base + 7)
            signature_length = tonumber(signature_length, 16)
            local signature = packet:sub(base + 8,base + 7 + signature_length*2)
            signature = utils.hexdecode(signature)
            subtree:add(signature_field, signature)
        end 
    end

    if(message_type_string == "SSH_MSG_USERAUTH_FAILURE") then
        local auth_methods_length = packet:sub(5,12)
        auth_methods_length = tonumber(auth_methods_length, 16)
        local auth_that_can_continue = packet:sub(13, 12 + auth_methods_length*2)
        auth_that_can_continue = utils.hexdecode(auth_that_can_continue)
        subtree:add(auth_that_can_continue_field, auth_that_can_continue)
        local base = 12 + auth_methods_length*2 + 1
        local partial_success = packet:sub(base,base + 1)
        partial_success = tonumber(partial_success, 16)
        if(partial_success == 0) then
            subtree:add(partial_success_field, "false")
        else
            subtree:add(partial_success_field, "true")
        end
    end

    if(message_type_string == "SSH_MSG_USERAUTH_SUCCESS") then
    end

    if(message_type_string == "SSH_MSG_USERAUTH_BANNER") then
        local message_length = packet:sub(5,12)
        message_length = tonumber(message_length, 16)
        local message = packet:sub(13,12 + message_length*2)
        message = utils.hexdecode(message)
        subtree:add(message_field, message)
        local base = 12 + message_length*2 + 1
        local language_tag_length = packet:sub(base,base + 7)
        language_tag_length = tonumber(language_tag_length, 16)
        local language_tag = packet:sub(base + 8,base + 7 + language_tag_length*2)
        language_tag = utils.hexdecode(language_tag)
        subtree:add(language_tag_field, language_tag)
    end

    if(message_type_string == "SSH_MSG_USERAUTH_PK_OK") then
        local algorithm_name_lenght = packet:sub(5,12)
        algorithm_name_lenght = tonumber(algorithm_name_lenght, 16)
        local algorithm_name = packet:sub(13,12 + algorithm_name_lenght*2)
        algorithm_name = utils.hexdecode(algorithm_name)
        subtree:add(public_key_alg_field, algorithm_name)
        local base = 12 + algorithm_name_lenght*2 + 1
        local blob_length = packet:sub(base,base + 7)
        blob_length = tonumber(blob_length, 16)
        local blob = packet:sub(base + 8,base + 7 + blob_length*2)
        subtree:add(publick_key_blob_field, blob)
    end
end

function parse_connection_protocol(packet, subtree, message_type_string)

    if(message_type_string == "SSH_MSG_CHANNEL_OPEN") then
        local channel_type_length = packet:sub(5,12)
        channel_type_length = tonumber(channel_type_length, 16)
        local channel_type = packet:sub(13,12 + channel_type_length*2)
        channel_type = utils.hexdecode(channel_type)
        subtree:add(channel_type_field, channel_type)
        local base = 12 + channel_type_length*2 + 1
        local channel_number = packet:sub(base,base + 7)
        channel_number = tonumber(channel_number, 16)
        subtree:add(channel_number_field, channel_number)
        base = base + 8
        local window_size = packet:sub(base,base + 7)
        window_size = tonumber(window_size, 16)
        subtree:add(window_size_field, window_size)
        base = base + 8
        local maximum_packet_size = packet:sub(base,base + 7)
        maximum_packet_size = tonumber(maximum_packet_size, 16)
        subtree:add(max_packet_size_field, maximum_packet_size)

        if(channel_type == "session") then
        elseif(channel_type == "x11") then
            base = base + 8
            local originator_address_length = packet:sub(base,base + 7)
            originator_address_length = tonumber(originator_address_length, 16)
            local originator_address = packet:sub(base + 8,base + 7 + originator_address_length*2)
            originator_address = utils.hexdecode(originator_address)
            subtree:add(originator_address_field, originator_address)
            local base = base + 7 + originator_address_length*2 + 1
            local originator_port = packet:sub(base,base + 7)
            originator_port = tonumber(originator_port, 16)
            subtree:add(originator_port_field, originator_port)
        elseif (channel_type == "forwarded-tcpip") then
            base = base + 8
            local originator_address_length = packet:sub(base,base + 7)
            originator_address_length = tonumber(originator_address_length, 16)
            local originator_address = packet:sub(base + 8,base + 7 + originator_address_length*2)
            originator_address = utils.hexdecode(originator_address)
            subtree:add(originator_address_field, originator_address)
            base = base + 7 + originator_address_length*2 + 1
            local originator_port = packet:sub(base,base + 7)
            originator_port = tonumber(originator_port, 16)
            subtree:add(originator_port_field, originator_port)
            base = base + 8
            local recipient_address_length = packet:sub(base,base + 7)
            recipient_address_length = tonumber(recipient_address_length, 16)
            local recipient_address = packet:sub(base + 8,base + 7 + recipient_address_length*2)
            recipient_address = utils.hexdecode(recipient_address)
            subtree:add(recipient_address_field, recipient_address)
            base = base + 7 + recipient_address_length*2 + 1
            local recipient_port = packet:sub(base,base + 7)
            recipient_port = tonumber(recipient_port, 16)
            subtree:add(recipient_port_field, recipient_port)
        elseif (channel_type == "direct-tcpip") then
            base = base + 8
            local recipient_address_length = packet:sub(base,base + 7)
            recipient_address_length = tonumber(recipient_address_length, 16)
            local recipient_address = packet:sub(base + 8,base + 7 + recipient_address_length*2)
            recipient_address = utils.hexdecode(recipient_address)
            subtree:add(recipient_address_field, recipient_address)
            base = base + 7 + recipient_address_length*2 + 1
            local recipient_port = packet:sub(base,base + 7)
            recipient_port = tonumber(recipient_port, 16)
            subtree:add(recipient_port_field, recipient_port)
            base = base + 8
            local originator_address_length = packet:sub(base,base + 7)
            originator_address_length = tonumber(originator_address_length, 16)
            local originator_address = packet:sub(base + 8,base + 7 + originator_address_length*2)
            originator_address = utils.hexdecode(originator_address)
            subtree:add(originator_address_field, originator_address)
            base = base + 7 + originator_address_length*2 + 1
            local originator_port = packet:sub(base,base + 7)
            originator_port = tonumber(originator_port, 16)
            subtree:add(originator_port_field, originator_port)
        end

    end

    if(message_type_string == "SSH_MSG_CHANNEL_OPEN_CONFIRMATION") then
        local channel_number = packet:sub(5,12)
        channel_number = tonumber(channel_number, 16)
        subtree:add(channel_number_field, channel_number)
        local base = 12 + 1
        local recipient_channel_number = packet:sub(base,base + 7)
        recipient_channel_number = tonumber(recipient_channel_number, 16)
        subtree:add(recipient_channel_number_field, recipient_channel_number)
        base = base + 8
        local window_size = packet:sub(base,base + 7)
        window_size = tonumber(window_size, 16)
        subtree:add(window_size_field, window_size)
        base = base + 8
        local maximum_packet_size = packet:sub(base,base + 7)
        maximum_packet_size = tonumber(maximum_packet_size, 16)
        subtree:add(max_packet_size_field, maximum_packet_size)
    end		

    if(message_type_string == "SSH_MSG_CHANNEL_OPEN_FAILURE") then
        local channel_number = packet:sub(5,12)
        channel_number = tonumber(channel_number, 16)
        subtree:add(channel_number_field, channel_number)
        local base = 12 + 1
        local reason_code = packet:sub(base,base + 7)
        reason_code = tonumber(reason_code, 16)
        subtree:add(reason_code_field, reason_code)
        base = base + 8
        local description_length = packet:sub(base,base + 7)
        description_length = tonumber(description_length, 16)
        local description = packet:sub(base + 8,base + 7 + description_length*2)
        description = utils.hexdecode(description)
        subtree:add(description_field, description)
        base = base + 7 + description_length*2 + 1
        local language_tag_length = packet:sub(base,base + 7)
        language_tag_length = tonumber(language_tag_length, 16)
        local language_tag = packet:sub(base + 8,base + 7 + language_tag_length*2)
        language_tag = utils.hexdecode(language_tag)
        subtree:add(language_tag_field, language_tag)
    end

    if(message_type_string == "SSH_MSG_CHANNEL_WINDOW_ADJUST") then
        channel_number = packet:sub(5,12)
        channel_number = tonumber(channel_number, 16)
        subtree:add(channel_number_field, channel_number)
        base = 12 + 1
        bytes_to_add = packet:sub(base,base + 7)
        bytes_to_add = tonumber(bytes_to_add, 16)
        subtree:add(bytes_to_add_field, bytes_to_add)
    end

    if(message_type_string == "SSH_MSG_CHANNEL_DATA") then
        channel_number = packet:sub(5,12)
        channel_number = tonumber(channel_number, 16)
        subtree:add(channel_number_field, channel_number)
        base = 12 + 1
        data_length = packet:sub(base,base + 7)
        data_length = tonumber(data_length, 16)
        data = packet:sub(base + 8,base + 7 + data_length*2)
        subtree:add(data_field, data)
    end

    if(message_type_string == "SSH_MSG_CHANNEL_EXTENDED_DATA") then
        channel_number = packet:sub(5,12)
        channel_number = tonumber(channel_number, 16)
        subtree:add(channel_number_field, channel_number)
        base = 12 + 1
        data_type_code = packet:sub(base,base + 7)
        data_type_code = tonumber(data_type_code, 16)
        subtree:add(data_type_code_field, data_type_code)
        base = base + 8
        data_length = packet:sub(base,base + 7)
        data_length = tonumber(data_length, 16)
        data = packet:sub(base + 8,base + 7 + data_length*2)
        subtree:add(data_field, data)
    end

    if(message_type_string == "SSH_MSG_CHANNEL_EOF") then
        channel_number = packet:sub(5,12)
        channel_number = tonumber(channel_number, 16)
        subtree:add(channel_number_field, channel_number)
    end

    if(message_type_string == "SSH_MSG_CHANNEL_CLOSE") then
        channel_number = packet:sub(5,12)
        channel_number = tonumber(channel_number, 16)
        subtree:add(channel_number_field, channel_number)
    end

    if(message_type_string == "SSH_MSG_CHANNEL_REQUEST") then
        local channel_number = packet:sub(5,12)
        channel_number = tonumber(channel_number, 16)
        subtree:add(channel_number_field, channel_number)
        local base = 12 + 1
        local request_type_length = packet:sub(base,base + 7)
        request_type_length = tonumber(request_type_length, 16)
        local request_type = packet:sub(base + 8,base + 7 + request_type_length*2)
        request_type = utils.hexdecode(request_type)
        subtree:add(request_type_field, request_type)

        base = base + 7 + request_type_length*2 + 1
        local want_reply = packet:sub(base,base + 1)
        want_reply = tonumber(want_reply, 16)
        subtree:add(want_reply_field, want_reply)
        base = base + 2
        
        if(request_type == "pty-req") then
            local terminal_mode_length = packet:sub(base,base + 7)
            terminal_mode_length = tonumber(terminal_mode_length, 16)
            local terminal_mode = packet:sub(base + 8,base + 7 + terminal_mode_length*2)
            terminal_mode = utils.hexdecode(terminal_mode)
            subtree:add(terminal_mode_field, terminal_mode)
            base = base + 7 + terminal_mode_length*2 + 1
            local terminal_width_characters = packet:sub(base,base + 7)
            terminal_width_characters = tonumber(terminal_width_characters, 16)
            subtree:add(terminal_width_characters_field, terminal_width_characters)
            base = base + 8
            local terminal_height_rows = packet:sub(base,base + 7)
            terminal_height_rows = tonumber(terminal_height_rows, 16)
            subtree:add(terminal_height_rows_field, terminal_height_rows)
            base = base + 8
            local terminal_width_pixels = packet:sub(base,base + 7)
            terminal_width_pixels = tonumber(terminal_width_pixels, 16)
            subtree:add(terminal_width_pixels_field, terminal_width_pixels)
            base = base + 8
            local terminal_height_pixels = packet:sub(base,base + 7)
            terminal_height_pixels = tonumber(terminal_height_pixels, 16)
            subtree:add(terminal_height_pixels_field, terminal_height_pixels)
            base = base + 8
            local encoded_terminal_modes_length = packet:sub(base,base + 7)
            encoded_terminal_modes_length = tonumber(encoded_terminal_modes_length, 16)
            local encoded_terminal_modes = packet:sub(base + 8,base + 7 + encoded_terminal_modes_length*2)
            encoded_terminal_modes = utils.hexdecode(encoded_terminal_modes)
            subtree:add(encoded_terminal_modes_field, encoded_terminal_modes)
        elseif(request_type == "x11-req") then
            local single_connection = packet:sub(base,base + 1)
            single_connection = tonumber(single_connection, 16)
            subtree:add(single_connection_field, single_connection)
            base = base + 2
            local x11_authentication_protocol_length = packet:sub(base,base + 7)
            x11_authentication_protocol_length = tonumber(x11_authentication_protocol_length, 16)
            local x11_authentication_protocol = packet:sub(base + 8,base + 7 + x11_authentication_protocol_length*2)
            x11_authentication_protocol = utils.hexdecode(x11_authentication_protocol)
            subtree:add(x11_authentication_protocol_field, x11_authentication_protocol)
            base = base + 7 + x11_authentication_protocol_length*2 + 1
            local x11_authentication_cookie_length = packet:sub(base,base + 7)
            x11_authentication_cookie_length = tonumber(x11_authentication_cookie_length, 16)
            local x11_authentication_cookie = packet:sub(base + 8,base + 7 + x11_authentication_cookie_length*2)
            x11_authentication_cookie = utils.hexdecode(x11_authentication_cookie)
            subtree:add(x11_authentication_cookie_field, x11_authentication_cookie)
            base = base + 7 + x11_authentication_cookie_length*2 + 1
            local x11_screen_number = packet:sub(base,base + 7)
            x11_screen_number = tonumber(x11_screen_number, 16)
            subtree:add(x11_screen_number_field, x11_screen_number)
        elseif(request_type == "env") then
            local variable_name_length = packet:sub(base,base + 7)
            variable_name_length = tonumber(variable_name_length, 16)
            local variable_name = packet:sub(base + 8,base + 7 + variable_name_length*2)
            variable_name = utils.hexdecode(variable_name)
            subtree:add(variable_name_field, variable_name)
            base = base + 7 + variable_name_length*2 + 1
            local variable_value_length = packet:sub(base,base + 7)
            variable_value_length = tonumber(variable_value_length, 16)
            local variable_value = packet:sub(base + 8,base + 7 + variable_value_length*2)
            variable_value = utils.hexdecode(variable_value)
            subtree:add(variable_value_field, variable_value)
        elseif(request_type == "subsystem") then
            local subsystem_name_length = packet:sub(base,base + 7)
            subsystem_name_length = tonumber(subsystem_name_length, 16)
            local subsystem_name = packet:sub(base + 8,base + 7 + subsystem_name_length*2)
            subsystem_name = utils.hexdecode(subsystem_name)
            subtree:add(subsystem_name_field, subsystem_name)
        elseif(request_type == "exec") then
            local command_length = packet:sub(base,base + 7)
            command_length = tonumber(command_length, 16)
            local command = packet:sub(base + 8,base + 7 + command_length*2)
            command = utils.hexdecode(command)
            subtree:add(command_field, command)
        elseif(request_type == "window-change") then
            local terminal_width_characters = packet:sub(base,base + 7)
            terminal_width_characters = tonumber(terminal_width_characters, 16)
            subtree:add(terminal_width_characters_field, terminal_width_characters)
            base = base + 8
            local terminal_height_rows = packet:sub(base,base + 7)
            terminal_height_rows = tonumber(terminal_height_rows, 16)
            subtree:add(terminal_height_rows_field, terminal_height_rows)
            base = base + 8
            local terminal_width_pixels = packet:sub(base,base + 7)
            terminal_width_pixels = tonumber(terminal_width_pixels, 16)
            subtree:add(terminal_width_pixels_field, terminal_width_pixels)
            base = base + 8
            local terminal_height_pixels = packet:sub(base,base + 7)
            terminal_height_pixels = tonumber(terminal_height_pixels, 16)
            subtree:add(terminal_height_pixels_field, terminal_height_pixels)
            base = base + 8
        elseif(request_type == "xon-xoff") then
            local client_can_do = packet:sub(base,base + 1)
            client_can_do = tonumber(client_can_do, 16)
            subtree:add(client_can_do_field, client_can_do)
        elseif(request_type == "signal") then
            local signal_name_length = packet:sub(base,base + 7)
            signal_name_length = tonumber(signal_name_length, 16)
            local signal_name = packet:sub(base + 8,base + 7 + signal_name_length*2)
            signal_name = utils.hexdecode(signal_name)
            subtree:add(signal_name_field, signal_name)
        elseif(request_type == "exit-status") then
            local exit_status = packet:sub(base,base + 7)
            exit_status = tonumber(exit_status, 16)
            subtree:add(exit_status_field, exit_status)
        elseif (request_type == "exit-signal") then
            local signal_name_length = packet:sub(base,base + 7)
            signal_name_length = tonumber(signal_name_length, 16)
            local signal_name = packet:sub(base + 8,base + 7 + signal_name_length*2)
            signal_name = utils.hexdecode(signal_name)
            subtree:add(signal_name_field, signal_name)
            base = base + 7 + signal_name_length*2 + 1
            local core_dumped = packet:sub(base,base + 1)
            core_dumped = tonumber(core_dumped, 16)
            subtree:add(core_dumped_field, core_dumped)
            base = base + 2
            local error_message_length = packet:sub(base,base + 7)
            error_message_length = tonumber(error_message_length, 16)
            local error_message = packet:sub(base + 8,base + 7 + error_message_length*2)
            error_message = utils.hexdecode(error_message)
            subtree:add(error_message_field, error_message)
            base = base + 7 + error_message_length*2 + 1
            local language_tag_length = packet:sub(base,base + 7)
            language_tag_length = tonumber(language_tag_length, 16)
            local language_tag = packet:sub(base + 8,base + 7 + language_tag_length*2)
            language_tag = utils.hexdecode(language_tag)
            subtree:add(language_tag_field, language_tag)
        end
    end

    if(message_type_string == "SSH_MSG_CHANNEL_SUCCESS") then 
        local channel_number = packet:sub(5, 12)
        channel_number = tonumber(channel_number, 16)
        subtree:add(channel_number_field, channel_number)

    end

    if(message_type_string == "SSH_MSG_CHANNEL_FAILURE") then 
        local channel_number = packet:sub(5, 12)
        channel_number = tonumber(channel_number, 16)
        subtree:add(channel_number_field, channel_number)
    end

    if(message_type_string == "SSH_MSG_GLOBAL_REQUEST") then
        local request_type_length = packet:sub(5,12)
        request_type_length = tonumber(request_type_length, 16)
        local request_type = packet:sub(13,12 + request_type_length*2)
        request_type = utils.hexdecode(request_type)
        base = 12 + request_type_length*2 + 1
        local want_reply = packet:sub(base,base + 1)
        want_reply = tonumber(want_reply, 16)
        base = base + 2
        local address_to_bind_length = packet:sub(base,base + 7)
        address_to_bind_length = tonumber(address_to_bind_length, 16)
        local address_to_bind = packet:sub(base + 8,base + 7 + address_to_bind_length*2)
        address_to_bind = utils.hexdecode(address_to_bind)
        base = base + 7 + address_to_bind_length*2 + 1
        local port_to_bind = packet:sub(base,base + 7)
        port_to_bind = tonumber(port_to_bind, 16)
        subtree:add(request_type_field, request_type)
        subtree:add(want_reply_field, want_reply)
        subtree:add(address_to_bind_field, address_to_bind)
        subtree:add(port_to_bind_field, port_to_bind)
    end
end

function m.parse(packet, pinfo, tree)
    local padding_length = packet:sub(1,2)
    padding_length = tonumber(padding_length, 16)
    

    if(packet:len() > 69) then
        tree:add(decrypted_data_field, packet:lower(), "Decrypted data: " .. packet:sub(1,69):lower() .. "…")
    else
        tree:add(decrypted_data_field, packet:lower())
    end

    tree:add(padding_length_field, padding_length)
    local padding = packet:sub(-(padding_length*2))
    tree:add(padding_field, padding)


    local msg_type = packet:sub(3,4)
    msg_type = tonumber(msg_type, 16)
    message_type_string = codes.message_types[msg_type]
    
    if(message_type_string == nil) then
        message_type_string = "unknown"
    end

    pinfo.cols.info:append(", " .. message_type_string .. " (" .. msg_type .. ")")

    tree:add(message_type_field, message_type_string)

    if(msg_type > 0 and msg_type < 49) then
        local subtree = tree:add(ssh_transport, "SSH Transport Layer Protocol")
        parse_transport_protocol(packet, subtree, message_type_string)
    elseif(msg_type >= 50  and msg_type <= 79) then
        local subtree = tree:add(ssh_auth, "SSH Authentication")
        parse_auth_protocol(packet, subtree, message_type_string)
    elseif(msg_type >= 80) then
        local subtree = tree:add(ssh_connection, "SSH Connection")
        parse_connection_protocol(packet, subtree, message_type_string)
    end
end

return m;