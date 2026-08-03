function EmptyState() {

    return (

        <div className="p-10 text-center">


            <div className="text-4xl mb-3">

                📡

            </div>


            <p className="text-slate-400">

                No events detected yet.

            </p>


            <p className="text-xs text-slate-600 mt-2">

                Waiting for ZD2 security events...

            </p>

        </div>

    );

}


export default EmptyState;