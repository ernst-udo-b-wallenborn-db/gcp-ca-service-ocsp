
all: server.exe genocsp.exe

clean:
	rm -f ~*
	rm -f .*~

distclean: clean
	rm -f *.exe

server.exe: server.go
	go build server.go

genocsp.exe: genocsp/genocsp.go
	go build genocsp/genocsp.go

