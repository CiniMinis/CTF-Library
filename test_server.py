import ctf_lib


def win1(client_sock):
	return True


challenge1 = ctf_lib.Challenge("Sample Challenge", 150, 4416, "flag1", win1)
challenge1.start_challenge()

while "stop" != raw_input().lower():
	pass

challenge1.stop_challenge()
