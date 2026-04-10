def extract_sni(data):
    try:
        if len(data) < 5:
            return None

        if data[0] != 0x16:
            return None

        if b"\x00\x00" in data:
            idx = data.find(b"\x00\x00")
            name_len = data[idx+3]
            server_name = data[idx+5:idx+5+name_len]
            return server_name.decode(errors="ignore")

    except:
        pass

    return None