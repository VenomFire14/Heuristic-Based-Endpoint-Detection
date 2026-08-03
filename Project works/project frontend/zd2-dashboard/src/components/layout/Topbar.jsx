import { useLocation } from "react-router-dom";


function Topbar() {

    const location = useLocation();


    const pageName = {

        "/dashboard": "Security Dashboard",

        "/alerts": "Security Alerts",

        "/attack-events": "Attack Events",

        "/hosts": "Monitored Hosts",

        "/source-ips": "Source IPs",

        "/threat-hunting": "Threat Hunting",

        "/analytics": "Security Analytics",

        "/settings": "Settings",

        "/profile": "Profile",

    };


    return (

        <header className="h-16 border-b border-slate-800 bg-slate-900 px-8 flex items-center justify-between">


            <div>

                <h2 className="text-xl font-semibold">

                    {pageName[location.pathname] || "ZD2"}

                </h2>


                <p className="text-xs text-slate-400">

                    Real-time system security monitoring

                </p>

            </div>



            <div className="flex items-center gap-4">


                <div className="flex items-center gap-2 text-sm">

                    <span className="w-2 h-2 bg-green-500 rounded-full"></span>

                    System Online

                </div>


                <div className="w-9 h-9 bg-slate-700 rounded-full flex items-center justify-center">

                    LC

                </div>

            </div>

        </header>

    );

}


export default Topbar;
