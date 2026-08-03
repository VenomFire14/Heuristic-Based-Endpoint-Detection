function LiveAttackFeed({
    events,
}) {

    const recentEvents =
        events
            .slice(-5)
            .reverse();


    return (

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">


            <div className="flex justify-between mb-5">


                <h3 className="font-semibold">

                    Live Attack Feed

                </h3>


                <span className="text-xs text-green-400">

                    ● LIVE

                </span>

            </div>



            <div className="space-y-4">


                {recentEvents.map(
                    (event, index) => (

                        <div
                            key={index}
                            className="flex gap-3"
                        >


                            <span className="w-2 h-2 rounded-full mt-2 bg-red-500" />


                            <div>

                                <p className="text-sm font-medium">

                                    {event.type}

                                </p>


                                <p className="text-xs text-slate-500">

                                    PID:{" "}

                                    {event.data?.pid || "-"}

                                </p>

                            </div>

                        </div>

                    )
                )}


                {events.length === 0 && (

                    <p className="text-sm text-slate-500">

                        Waiting for security events...

                    </p>

                )}

            </div>

        </div>

    );

}


export default LiveAttackFeed;