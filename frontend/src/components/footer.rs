use chrono::Datelike;
use yew::prelude::*;

#[function_component(Footer)]
pub fn footer() -> Html {
    let year = chrono::Utc::now().year(); // Get the current year
    let app_name = "Web Sands"; // Use the APP_NAME from environment variables

    html! {
        <footer class="c-footer">
            <div class="c-footer__container">
                <p class="c-footer__copyright">{ format!("© {} {}. All rights reserved.", year, app_name) }</p>
            </div>
        </footer>
    }
}
