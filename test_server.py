import ctf_lib


def win1(client_sock, ip):
	return True


challenge1 = ctf_lib.Challenge("Sample_Challenge1", 150, 4416, "flag1", win1,
							   True)
challenge2 = ctf_lib.Challenge("Sample_Challenge2", 150, 2231, "flag2", win1,
							   True)
challenge3 = ctf_lib.Challenge("Sample_Challenge3", 150, 2212, "flag3", win1)

ctf = ctf_lib.CTF([challenge1, challenge2], 1234)
ctf.start_all()
ctf.add_challenge(challenge3)
ctf.start_by_name(challenge3.name)

while "stop" != raw_input().lower():
	pass

ctf.stop_by_name(challenge1.name)
ctf.stop_all()
print ctf.leader_board

