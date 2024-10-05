use yew::prelude::*;

#[function_component(Dashboard)]
pub fn dashboard() -> Html {
    html! {
        <main class="dashboard-content">
            <h1>{ "OxidizedOasis-WebSands Dashboard" }</h1>
            <p>
                { "Welcome to your dashboard. This area is currently under construction." }
            </p>
            <div class="dashboard-placeholder">
                <h2>{ "Coming Soon" }</h2>
                <ul>
                    <li>{ "User Profile Management" }</li>
                    <li>{ "Account Settings" }</li>
                    <li>{ "Activity Logs" }</li>
                    <li>{ "Security Settings" }</li>
                </ul>
            </div>
            <p>
                { "Thank you for your patience as we develop these features to enhance your experience with OxidizedOasis-WebSands." }
            </p>
        </main>
    }
}