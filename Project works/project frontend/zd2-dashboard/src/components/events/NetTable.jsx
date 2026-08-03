function NetTable({
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
                        Command
                    </th>

                    <th>
                        Destination IP
                    </th>

                    <th>
                        Port
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

                                        <span className="px-3 py-1 rounded-full text-xs bg-blue-500/10 text-blue-400">

                                            NET

                                        </span>

                                    </td>


                                    <td>
                                        {d.pid || "-"}
                                    </td>


                                    <td>
                                        {d.comm || "-"}
                                    </td>


                                    <td>
                                        {d.ip || "-"}
                                    </td>


                                    <td>
                                        {d.port || "-"}
                                    </td>

                                </tr>

                            );

                        }
                    )}

            </tbody>

        </table>

    );

}


export default NetTable;