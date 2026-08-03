function EventTabs({
    activeTab,
    setActiveTab,
    events,
}) {


    const alertCount =
        events.filter(
            (event) =>
                event.type === "ALERT"
        ).length;


    const execveCount =
        events.filter(
            (event) =>
                event.type === "EXECVE"
        ).length;


    const netCount =
        events.filter(
            (event) =>
                event.type === "NET"
        ).length;


    const tabs = [

        {
            name: "ALERT",
            count: alertCount,
        },

        {
            name: "EXECVE",
            count: execveCount,
        },

        {
            name: "NET",
            count: netCount,
        },

    ];


    return (

        <div className="flex gap-2 mt-6">


            {tabs.map(
                (tab) => (

                    <button
                        key={tab.name}
                        onClick={() =>
                            setActiveTab(tab.name)
                        }
                        className={`px-5 py-2 rounded-lg text-sm font-medium ${activeTab === tab.name
                                ? "bg-blue-600 text-white"
                                : "bg-slate-800 text-slate-400 hover:bg-slate-700 hover:text-white"
                            }`}
                    >

                        {tab.name}


                        <span className="ml-2 opacity-70">

                            {tab.count}

                        </span>

                    </button>

                )
            )}

        </div>

    );

}


export default EventTabs;