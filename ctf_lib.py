import socket
import threading
import hashlib


class Challenge:
	""" The base class of the library, represents a single ctf challenge
	"""
	__challenge_count = 0		# challenge count for id determination
	__SERVER_IP = "0.0.0.0"
	
	def __init__(self, name, pts, port, flag, win_func, unique_flag=False,
														sock_timeout=0.5):
		"""
		Constructor for a challenge
		
		Args:
			name (str): A name for the challenge. Preferably unique.
			pts (int): The number of points awarded for completing
				the challenge.
			port (int): Port which contains the challenge
			flag (str): The challenge's flag
			win_func (function(:obj: socket, :str: ip) returns 'bool'): Win
				function. Gets a client socket (with which to
				communicate) and the client's ip and returns a boolean
				representing whether
				the flag should be sent back or not.
			unique_flag (bool): if True generates unique flags per ip
			sock_timeout (float): Timeout for listening for connections. Acts
				as cycle time for checking if the challenge got closed.
				Defaults to 0.5.
		"""
		Challenge.__challenge_count += 1
		self.__id = self.__challenge_count
		self.__name = name
		self.__pts = pts
		self.__port = port
		self.__flag = flag
		self.__win_func = win_func
		self.__unique_flag = unique_flag
		
		if sock_timeout > 0:
			self.__timeout = sock_timeout
		else:
			raise TypeError('sock_timeout must be positive')

		self.__challenge = threading.Thread(target=self.__start_challenge)
		self.__is_stopped = False

	def start_challenge(self):
		"""
		Starts the Challenge. Calling will start handling clients in the
		given IP and port.
		"""
		self.__is_stopped = False
		self.__challenge.start()

	def __handle_client(self, client_sock, address):
		if self.__win_func(client_sock, address[0]):
			if self.__unique_flag:
				md5 = hashlib.md5(self.__flag + address[0]).hexdigest()
				client_sock.send(md5 + "\n")
			else:
				client_sock.send(self.__flag + "\n")
		client_sock.close()
		print "[*] %s disconnected [*]" % address[0]

	def __start_challenge(self):
		server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		server_sock.bind((Challenge.__SERVER_IP, self.__port))
		server_sock.settimeout(self.__timeout)
	
		while not self.__is_stopped:
			try:
				server_sock.listen(1)
				client_sock, address = server_sock.accept()
				print "[*] %s connected to %s [*]" % (address[0], self.__name)
				threading.Thread(target=self.__handle_client, args=(
					client_sock, address,)).start()
			except socket.timeout:
				pass
			except Exception as e:
				print "[*] Exception (%s) [*]" % e.message
				self.stop_challenge()
	
		print "[*] Goodbye! [*]"
		server_sock.close()

	def stop_challenge(self):
		"""
		Stops the challenge. Calling will stop handling clients in the
		given IP and port.
		"""
		self.__is_stopped = True
		
	def is_running(self):
		"""
		Checks the challenge state
		
		Returns:
			True if currently running, False if stopped.
		"""
		return not self.__is_stopped
	
	@property
	def id(self):
		"""
		Retrieves the challenge id
		
		Returns:
			int: The challenge id
		"""
		return self.__id
	
	@property
	def name(self):
		"""
		Retrieves the challenge's name
		
		Returns:
			str: The challenge's name
		"""
		return self.__name
	
	@name.setter
	def name(self, name):
		"""
		Renames the challenge
		
		Args:
			name (str): The new name
		"""
		self.__name = name
	
	@property
	def pts(self):
		"""
		Retrieves the challenge's points
		
		Returns:
			int: The point worth of the challenge
		"""
		return self.__pts
	
	@pts.setter
	def pts(self, pts):
		"""
		Resets the challenge's points
		
		Args:
			pts (int): The new amount of points awarded by the challenge
		"""
		self.__pts = pts
	
	@property
	def port(self):
		"""
		Retrieves the challenge's port
		
		Returns:
			int: The port on which the challenge is hosted
		"""
		return self.__port
	
	@property
	def flag(self):
		"""
		Retrieves the challenge's flag
		
		Returns:
			str: The flag required to beat the challenge
		"""
		return self.__flag
		
	@property
	def win_func(self):
		"""
		Retrieves the challenge's main function
		
		Returns:
			function: The function with which players play
		"""
		return self.__win_func
	
	@property
	def sock_timeout(self):
		"""
		Retrieves the challenge's socket timeout
		
		Returns:
			float: The number of seconds it takes for the 
			server to check again for a server close
		"""
		return self.__timeout

	@property
	def unique_flag(self):
		"""
		Retrieves the challenge's unique_flag boolean

		Returns:
			bool: True if the challenge generates unique flags, False Otherwise
		"""
		return self.__unique_flag


class User:
	"""User class used to hold data
	"""
	def __init__(self, ip, name="User"):
		self.__solved = []
		self.__ip = ip
		self.__name = name

	def solve(self, challenge, attempt):
		if challenge.unique_flag:
			answer = hashlib.md5(challenge.flag + self.__ip).hexdigest()
		else:
			answer = challenge.flag
		if answer == attempt and challenge not in self.__solved:
			self.__solved.append(challenge)
			return True
		return False

	@property
	def points(self):
		pts = 0
		for challenge in self.__solved:
			pts += challenge.pts
		return pts

	@property
	def ip(self):
		return self.__ip

	@property
	def name(self):
		return self.__name

	@name.setter
	def name(self, new):
		self.__name = new

	def __lt__(self, other):
		return self.points < other.points

	def __str__(self):
		return "%s(%s) with %d points" % (self.__name, self.__ip, self.points)


class CTF:
	""" A class which handles multiple CTFs
	"""
	
	def __init__(self, challenges=None, main_port=None, unique_flag=None):
		self.__challenges = {}
		if challenges is None:
			return
		for challenge in challenges:
			if main_port is not None and main_port == challenge.port:
				raise(TypeError, "challenge port mustn't equal the main port")
			if unique_flag is not None and unique_flag != challenge.unique_flag:
				raise (TypeError, "challenge unique flag doesn't match")
			self.add_challenge(challenge)
		if main_port is not None:
			self.add_challenge(Challenge("Menu Shell", 0, main_port, "flag",
											self.__shell))
		self.__main_port = main_port
		self.__users = {}
		self.__is_active = False

	def get(self, challenge_id):
		try:
			return self.__challenges[challenge_id]
		except KeyError:
			return None

	def start_all(self):
		self.__is_active = True
		for challenge in self.__challenges.itervalues():
			challenge.start_challenge()

	def stop_all(self):
		self.__is_active = False
		for challenge in self.__challenges.itervalues():
			challenge.stop_challenge()

	def start_challenge(self, challenge_id):
		self.__is_active = True
		if self.get(challenge_id) is not None:
			self.get(challenge_id).start_challenge()

	def start_by_name(self, name):
		challenge_id = self.id_by_name(name)
		if challenge_id is not None:
			self.start_challenge(challenge_id)

	def stop_challenge(self, challenge_id):
		if self.get(challenge_id) is not None:
			self.get(challenge_id).stop_challenge()
		for challenge in self.__challenges.itervalues():
			if challenge.is_running() and challenge.port != self.__main_port:
				return
		self.__is_active = False

	def stop_by_name(self, name):
		challenge_id = self.id_by_name(name)
		if challenge_id is not None:
			self.stop_challenge(challenge_id)

	def add_challenge(self, challenge):
		self.__challenges[challenge.id] = challenge

	def id_by_name(self, name):
		for challenge in self.__challenges.itervalues():
			if challenge.name == name:
				return challenge.id
		return None

	def __solve(self, ip, name, attempt):
		user = self.__users[ip]
		if user is None:
			return False
		challenge_id = self.id_by_name(name)
		if challenge_id is None:
			return False
		challenge = self.__challenges[challenge_id]
		if challenge is None:
			return False
		return user.solve(challenge, attempt)

	def __shell(self, client_sock, ip):		# stopped working here
		if ip not in self.__users.iterkeys():
			self.__users[ip] = User(ip)
		client_sock.send("Welcome to the CTF! What would you like to do?\n")
		client_sock.settimeout(None)
		while self.__is_active:
			buff = client_sock.recv(1024).replace("\n", " ")
			cmd = buff.split(" ")[0].lower()
			print "\"" + cmd + "\""
			if cmd == "solve":
				if len(buff.split(" "))-1 == 3:
					if self.__solve(ip, buff.split(" ")[1], buff.split(" ")[2]):
						client_sock.send("Challenge Solved!\n")
					else:
						client_sock.send("Solve Failed!\n")
				else:
					client_sock.send("Usage: solve challenge_name flag\n")
			elif cmd == "points":
				pts = self.__users[ip].points
				client_sock.send("You have %d points\n" % pts)
			elif cmd == "whoami":
				name = self.__users[ip].name
				client_sock.send("You are %s\n" % name)
			elif cmd == "rename":
				if len(buff.split(" "))-1 == 2:
					self.__users[ip].name = buff.split(" ")[1]
					client_sock.send("Renamed to %s\n" % self.__users[ip].name)
				else:
					client_sock.send("Usage: rename new_name\n")
			elif cmd == "exit":
				return False
			else:
				client_sock.send("Excuse me, what?\n")

	@property
	def is_active(self):
		return self.__is_active

	@property
	def leader_board(self):
		score = sorted(self.__users.itervalues())
		board = "Leader Board:\n"
		for rank, user in enumerate(score):
			board = board + "%d) %s" % (rank+1, str(user))
		return board




