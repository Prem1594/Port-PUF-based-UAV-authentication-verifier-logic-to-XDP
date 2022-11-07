# TiN_Project

# Instructions for execution:

1. Open Terminal and check for the current list of containers running using the command
    sudo docker ps.

2. Check the saved states of the containers using the command
    sudo docker images

3. From the list of saved images, open the containers that are saved latest using the command
    sudo docker run -it <repository>:<tag> bin/bash
    it opens a container (for server/verifier)

4. Type ifconfig in the new container. Get its ip address details.

5. Type ifconfig in the host terminal window and see the virtual ethernet interface added
    Let it be vethserver.

6. Using the same command in the 3, open a new container for the client also.

7. Type ifconfig in the client container and get its ip address.

8. Type ifconfig in the host terminal window and see the virtual ethernet interface newly added
    Let it be vethclient.

9. Compile the server program from the server container, and client program from the client container using the gcc <filename> -o <executable_file_name>.

10. Compile the xdp program from the host terminal window using the following command.

clang -O2 -g -Wall -target bpf -c parse_hook.c -o parse_hook.o
Note: parse_hook.c is the xdp program and parse_hook.o is the executable generated.

11. After compiling, we need to hook it to the veth interface of the server using  the following command.
sudo ip link set vethserver xdpgeneric obj parse_hook.o sec ingress
Note: ingress is the section in the xdp program.

12. To unhook a xdp program, use the below command.
    sudo ip link set vethserver xdpgeneric off.

13. Run the server in its container, and client in the client's container.

14. We can see the debug statements output by using the below command in the host terminal window.
sudo cat /sys/kernel/tracing/trace_pipe.
