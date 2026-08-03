import StatCards
    from "../components/dashboard/StatCards";

import AttackActivity
    from "../components/dashboard/AttackActivity";

import LiveAttackFeed
    from "../components/dashboard/LiveAttackFeed";

import SecurityEvents
    from "../components/events/SecurityEvents";

import useSecurityEvents
    from "../hooks/useSecurityEvents";


function Dashboard() {

    const {
        events,
        connected,
    } = useSecurityEvents();


    return (

        <section className="p-8">


            {/* STAT CARDS */}

            <StatCards
                events={events}
            />


            {/* CHART + LIVE FEED */}

            <div className="grid grid-cols-3 gap-6 mb-8">


                <AttackActivity />


                <LiveAttackFeed
                    events={events}
                />

            </div>


            {/* REAL-TIME EVENTS */}

            <SecurityEvents
                events={events}
                connected={connected}
            />


        </section>

    );

}


export default Dashboard;