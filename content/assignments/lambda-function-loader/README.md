
# Project Title

Team: Cîrstescu Andrei-Vlad 321CC, Stiuj Emanuel-Ștefan 321CC

[Repository link](https://github.com/androfon69/Hackathon)

The server is implemented using Unix sockets. It can handle multiples requests
by creating a __daemon__ for each client that handles the execution and output
of the lambda functions. 

Upon any kind of failure, the daemon process exits and doesn't affect the main
server.