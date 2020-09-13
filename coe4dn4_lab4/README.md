This lab is to develop a client and server that implements multi-group online chatting. The
server code operates as a directory manager for online chat rooms. The clients can dynamically
create, delete and join chat rooms. After joining a chat room, the client software exchanges
messages with other clients using IP multicast communications. We defined the CMD as
follows: connect getdir, makerrom, deleteroom , name , chat , bye
TCP socket is created to communicate with the server and UDP is used to communicate
between the clients in the chat room. The client creates the chat room by sending the necessary
info to the server which then creates a list containing the name of the chatroom, address and
port number. The client also sends the necessary info to the server corresponding to the
commands inputted by the user. The server splits the message send by the client and stores it
in the correct variables. The select function is used to wait on a number of sockets to have data
to be read. If at least one socket has something to be read, loop through that socket. If one
socket is a new connection, add it to the chat room.
