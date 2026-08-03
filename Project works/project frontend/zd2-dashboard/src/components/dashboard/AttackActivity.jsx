function AttackActivity() {

    const bars = [
        40,
        70,
        45,
        90,
        60,
        80,
        50,
        100,
        65,
        75,
        55,
        85,
    ];


    return (

        <div className="col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-6">


            <div className="flex justify-between mb-6">


                <div>

                    <h3 className="font-semibold">

                        Attack Activity

                    </h3>


                    <p className="text-xs text-slate-400">

                        Number of detected attacks

                    </p>

                </div>


                <select className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm">

                    <option>
                        Last 24 Hours
                    </option>

                    <option>
                        Last 7 Days
                    </option>

                    <option>
                        Last 30 Days
                    </option>

                </select>

            </div>



            <div className="h-64 flex items-end gap-4 border-b border-slate-700">


                {bars.map(
                    (height, index) => (

                        <div
                            key={index}
                            className="flex-1 bg-blue-600 rounded-t-md"
                            style={{
                                height: `${height}%`,
                            }}
                        />

                    )
                )}

            </div>

        </div>

    );

}


export default AttackActivity;