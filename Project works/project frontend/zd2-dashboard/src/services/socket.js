import { io } from "socket.io-client";


// Change this URL according to your Ubuntu backend.
//
// Example:
//
// const SOCKET_URL = "http://192.168.1.100:5000";

const SOCKET_URL = "http://YOUR_UBUNTU_IP:YOUR_PORT";


const socket = io(SOCKET_URL, {
    transports: ["websocket"],
});


export default socket;