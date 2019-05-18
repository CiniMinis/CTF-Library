import socket
import threading


class Challenge:
	""" The base class of the library, represents a single ctf challenge
	"""
	__challenge_count = 0		# challenge count for id determination
	
	def __init__(self, name, pts, port, flag, win_func, ip="127.0.0.1",
														sock_timeout=0.5):
		"""
		Constructor for a challenge
		
		Args:
			name (str): A name for the challenge. Preferably unique.
			pts (int): The number of points awarded for completing
				the challenge.
			port (int): Port which contains the challenge
			flag (str): The challenge's flag
			win_func (function(:obj: socket) returns 'bool'): Win
				function. Gets a client socket (with which to
				communicate) and returns a boolean representing whether
				the flag should be sent back or not.
			ip (str): The servers ip. Defaults to "127.0.0.1".
			sock_timeout (float): Timeout for listening for connections. Acts
				as cycle time for checking if the challenge got closed.
				Defaults to 0.5.
		"""
		self.__challenge_count += 1
		self.__id = self.__challenge_count
		self.__name = name
		self.__pts = pts
		self.__port = port
		self.__flag = flag
		self.__win_func = win_func
		self.__ip = ip
		
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
		if self.__win_func(client_sock):
			print "[*] %s won! Giving flag [*]" % address[0]
			client_sock.send(self.__flag + "\n")
		else:
			print "[*] %s didn't win [*]" % address[0]
		client_sock.close()

	def __start_challenge(self):
		server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		server_sock.bind((self.__ip, self.__port))
		server_sock.settimeout(self.__timeout)
	
		while not self.__is_stopped:
			try:
				server_sock.listen(1)
				client_sock, address = server_sock.accept()
				print "[*] %s connected [*]" % address[0]
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
	def ip(self):
		"""
		Retrieves the challenge's ip
		
		Returns:
			str: The ip of the challenge server
		"""
		return self.__ip
		
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


class CTF:
	""" A class which handles multiple CTFs
	"""
	
	def __init__(self):
		pass
