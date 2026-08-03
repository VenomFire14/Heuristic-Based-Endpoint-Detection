import {
    useMemo,
    useState,
} from "react";


import EventTabs
    from "./EventTabs";

import AlertTable
    from "./AlertTable";

import ExecveTable
    from "./ExecveTable";

import NetTable
    from "./NetTable";

import EmptyState
    from "./EmptyState";


function SecurityEvents({
    events,
    connected,
}) {


    const [
        activeTab,
        setActiveTab,
    ] = useState("ALERT");


    const filteredEvents =
        useMemo(() => {

            return events.filter(
                (event) =>
                    event.type === activeTab
            );

        }, [
            events,
            activeTab,
        ]);


    return (

        <div className="bg-slate-900 border border-slate-800 rounded-xl">


            {/* HEADER */}

            <div className="p-6 border-b border-slate-800">


                <div className="flex justify-between">


                    <div>

                        <h3 className="font-semibold">

                            Recent Security Events

                        </h3>


                        <p className="text-xs text-slate-400 mt-1">

                            Real-time events detected by ZD2

                        </p>

                    </div>


                    <div
                        className={
                            connected
                                ? "text-xs text-green-400"
                                : "text-xs text-red-400"
                        }
                    >

                        ●{" "}

                        {connected
                            ? "LIVE"
                            : "OFFLINE"}

                    </div>

                </div>


                {/* TABS */}

                <EventTabs
                    activeTab={activeTab}
                    setActiveTab={setActiveTab}
                    events={events}
                />

            </div>



            {/* EVENT CONTENT */}

            <div className="overflow-x-auto">


                {filteredEvents.length === 0 && (

                    <EmptyState />

                )}


                {activeTab === "ALERT" &&
                    filteredEvents.length > 0 && (

                        <AlertTable
                            events={filteredEvents}
                        />

                    )}


                {activeTab === "EXECVE" &&
                    filteredEvents.length > 0 && (

                        <ExecveTable
                            events={filteredEvents}
                        />

                    )}


                {activeTab === "NET" &&
                    filteredEvents.length > 0 && (

                        <NetTable
                            events={filteredEvents}
                        />

                    )}

            </div>

        </div>

    );

}


export default SecurityEvents;