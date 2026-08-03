const stats = [
    {
        title: "Total Events",
        icon: "⚔️",
    },

    {
        title: "Critical Alerts",
        icon: "🔴",
    },

    {
        title: "Network Events",
        icon: "🌐",
    },

    {
        title: "Process Events",
        icon: "🖥️",
    },
];


function StatCards({ events }) {


    const totalEvents =
        events.length;


    const alertEvents =
        events.filter(
            (event) =>
                event.type === "ALERT"
        ).length;


    const netEvents =
        events.filter(
            (event) =>
                event.type === "NET"
        ).length;


    const execveEvents =
        events.filter(
            (event) =>
                event.type === "EXECVE"
        ).length;


    const values = [

        totalEvents,

        alertEvents,

        netEvents,

        execveEvents,

    ];


    return (

        <div className="grid grid-cols-4 gap-5 mb-8">


            {stats.map(
                (stat, index) => (

                    <div
                        key={stat.title}
                        className="bg-slate-900 border border-slate-800 rounded-xl p-5"
                    >


                        <div className="flex justify-between items-center">


                            <div>

                                <p className="text-sm text-slate-400">

                                    {stat.title}

                                </p>


                                <h3 className="text-3xl font-bold mt-2">

                                    {values[index]}

                                </h3>

                            </div>


                            <div className="text-2xl">

                                {stat.icon}

                            </div>


                        </div>

                    </div>

                )

            )}

        </div>

    );

}


export default StatCards;