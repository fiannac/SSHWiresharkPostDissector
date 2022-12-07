do
	local cipher = require('openssl').cipher

	package.prepend_path("plugins/ssh_postdissector")

	local utils = require("utils")
	local codes = require("codes")
	local init = require("init")
	local parser = require("parser")

	init.create_dissector();

	function ssh_decrypt.init()
		state = {}
		data_client = ''
		data_server = ''
		
		if(ssh_decrypt.prefs.encryption_alg == 1) then
			alg_name = 'aes-128-cbc'
		elseif(ssh_decrypt.prefs.encryption_alg == 2) then
			alg_name = 'aes-128-ctr'
		elseif(ssh_decrypt.prefs.encryption_alg == 3) then
			alg_name = '3des-cbc'
		end

		alg = cipher.get(alg_name)
	end

	function ssh_decrypt.dissector(buffer,pinfo,tree)
		if(p.enable == false) then
			return
		end

		local enc_data = ssh_encrypted_data()
		if enc_data then
			enc_data = tostring(enc_data)
			enc_data = enc_data:gsub(":", "")
			local num = packet_number().value
			local dir = tostring(direction())

			local client_key = utils.fromhex(p.ck)
			local client_iv = utils.fromhex(p.civ)
			local server_key = utils.fromhex(p.sk)
			local server_iv = utils.fromhex(p.siv)

			local curr_len = packet_length().value

			local padd = ssh_padding_length()
			if padd then
				curr_len = enc_data:len() / 2
			end

			local remaning = enc_data:len() / 2
			local i = 0
			local base_position = 0

			while remaning > 0 do
				local subtree = tree:add(ssh_decrypt, "SSH Decrypted Payload")

				if state[num .. " " .. i] == nil then
					local curr_enc_data = enc_data:sub(1 + base_position, base_position + curr_len * 2)
					if dir =="0" then -- client
						local begin_s = 1 + data_client:len()
						local end_s = begin_s + curr_enc_data:len() - 1
						data_client = data_client .. curr_enc_data
						res = alg:decrypt(utils.fromhex(data_client), client_key, client_iv, false)	
						res = utils.tohex(res)
						res = res:sub(begin_s, end_s)
						state[num .. " " .. i] = res
					else
						local begin_s = 1 + data_server:len()
						local end_s = begin_s + curr_enc_data:len() - 1
						data_server = data_server .. curr_enc_data
						res = alg:decrypt(utils.fromhex(data_server), server_key, server_iv, false)
						res = utils.tohex(res)
						res = res:sub(begin_s, end_s)
						state[num .. " " .. i] = res
					end
				end

				parser.parse(state[num .. " " .. i], pinfo, subtree)

				remaning = remaning - curr_len
				if(remaning > 0) then
					base_position = base_position + 1 + curr_len * 2 + 32 * 2
					curr_len = tonumber(enc_data:sub(base_position, base_position + 7), 16)
					base_position = base_position + 7
					i = i + 1
					remaning = remaning - 32 - 4
				end

			end
		end
	end

	register_postdissector(ssh_decrypt)
end