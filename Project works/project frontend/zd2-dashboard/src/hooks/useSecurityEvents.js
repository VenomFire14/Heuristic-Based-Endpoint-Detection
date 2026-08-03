import {
    useEffect,
    useState,
} from "react";

import socket from "../services/socket";


function useSecurityEvents() {

    const [events, setEvents] = useState([]);

    const [connected, setConnected] =
        useState(false);


    useEffect(() => {


        // SOCKET CONNECTED

        const handleConnect = () => {

            console.log(
                "Connected to ZD2 Socket.IO server"
            );

            setConnected(true);

        };


        // SOCKET DISCONNECTED

        const handleDisconnect = () => {

            console.log(
                "Disconnected from server"
            );

            setConnected(false);

        };


        // OLD HISTORY

        const handleHistory = (historyData) => {

            console.log(
                "Received event history:",
                historyData
            );

            setEvents(historyData);

        };


        // NEW REAL-TIME EVENT

        const handleNewEvent = (data) => {

            console.log(
                "New ZD2 event:",
                data
            );


            setEvents((previousEvents) => [

                ...previousEvents,

                data,

            ]);

        };


        socket.on(
            "connect",
            handleConnect
        );


        socket.on(
            "disconnect",
            handleDisconnect
        );


        socket.on(
            "log_history",
            handleHistory
        );


        socket.on(
            "new_log_data",
            handleNewEvent
        );


        // CLEANUP

        return () => {

            socket.off(
                "connect",
                handleConnect
            );

            socket.off(
                "disconnect",
                handleDisconnect
            );

            socket.off(
                "log_history",
                handleHistory
            );

            socket.off(
                "new_log_data",
                handleNewEvent
            );

        };

    }, []);


    return {

        events,

        connected,

    };

}


export default useSecurityEvents;