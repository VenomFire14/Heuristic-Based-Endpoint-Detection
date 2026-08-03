function AlertTable({
    events,
}) {

    return (

        <table className="w-full">


            <thead className="text-left text-xs text-slate-400 bg-slate-800/40">

                <tr>

                    <th className="px-6 py-4">
                        Type
                    </th>

                    <th>
                        PID
                    </th>

                    <th>
                        UID
                    </th>

                    <th>
                        Command
                    </th>

                    <th>
                        Target PID
                    </th>

                </tr>

            </thead>



            <tbody>


                {events
                    .slice()
                    .reverse()
                    .map(
                        (event, index) => {

                            const d =
                                event.data || {};


                            return (

                                <tr
                                    key={index}
                                    className="border-t border-slate-800 hover:bg-slate-800/40"
                                >

                                    <td className="px-6 py-4">

                                        <span className="px-3 py-1 rounded-full text-xs bg-red-500/10 text-red-400">

                                            ALERT

                                        </span>

                                    </td>


                                    <td>
                                        {d.pid || "-"}
                                    </td>


                                    <td>
                                        {d.uid || "-"}
                                    </td>


                                    <td>
                                        {d.comm || "-"}
                                    </td>


                                    <td>
                                        {d.tracee_pid || "-"}
                                    </td>

                                </tr>

                            );

                        }
                    )}

            </tbody>

        </table>

    );

}


export default AlertTable;