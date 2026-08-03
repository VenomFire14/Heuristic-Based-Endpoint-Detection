import { NavLink } from "react-router-dom";


const menuItems = [

    {
        path: "/dashboard",
        icon: "📊",
        text: "Dashboard",
    },



    {
        path: "/alerts",
        icon: "🚨",
        text: "Alerts",
    },

    {
        path: "/attack-events",
        icon: "⚔️",
        text: "Attack Events",
    },

    {
        path: "/hosts",
        icon: "🖥️",
        text: "Hosts",
    },

    {
        path: "/source-ips",
        icon: "🌐",
        text: "Source IPs",
    },

    {
        path: "/threat-hunting",
        icon: "🔍",
        text: "Threat Hunting",
    },

    {
        path: "/analytics",
        icon: "📈",
        text: "Analytics",
    },

];


function Sidebar() {

    return (

        <aside className="w-64 bg-slate-900 border-r border-slate-800 p-5 relative">


            {/* LOGO */}

            <div className="flex items-center gap-3 mb-10">

                <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">

                    🛡️

                </div>


                <div>

                    <h1 className="font-bold text-lg">
                        ZD2
                    </h1>

                    <p className="text-xs text-slate-400">
                        Security Platform
                    </p>

                </div>

            </div>


            {/* MAIN MENU */}

            <nav className="space-y-2">

                {menuItems.map((item) => (

                    <NavLink
                        key={item.path}
                        to={item.path}
                        className={({ isActive }) =>

                            `flex items-center gap-3 px-4 py-3 rounded-lg transition ${isActive
                                ? "bg-blue-600 text-white"
                                : "text-slate-400 hover:bg-slate-800 hover:text-white"
                            }`

                        }
                    >

                        <span>
                            {item.icon}
                        </span>

                        <span className="text-sm font-medium">

                            {item.text}

                        </span>

                    </NavLink>

                ))}

            </nav>


            {/* BOTTOM MENU */}

            <div className="absolute bottom-5 left-5 right-5 space-y-2">


                <NavLink
                    to="/settings"
                    className={({ isActive }) =>

                        `flex items-center gap-3 px-4 py-3 rounded-lg ${isActive
                            ? "bg-blue-600 text-white"
                            : "text-slate-400 hover:bg-slate-800 hover:text-white"
                        }`

                    }
                >

                    ⚙️

                    <span className="text-sm">
                        Settings
                    </span>

                </NavLink>


                <NavLink
                    to="/profile"
                    className={({ isActive }) =>

                        `flex items-center gap-3 px-4 py-3 rounded-lg ${isActive
                            ? "bg-blue-600 text-white"
                            : "text-slate-400 hover:bg-slate-800 hover:text-white"
                        }`

                    }
                >

                    👤

                    <span className="text-sm">
                        Profile
                    </span>

                </NavLink>

            </div>

        </aside>

    );

}


export default Sidebar;