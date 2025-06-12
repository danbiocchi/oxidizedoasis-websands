use yew::prelude::*;
use yew_router::prelude::*;
use crate::routes::Route; // Assuming Route is in crate::routes

// Represents a single item in the breadcrumb trail
#[derive(Clone, PartialEq, Properties)]
pub struct BreadcrumbItemProps {
    pub label: String,
    pub path: Option<Route>, // Option because the last item might not be a link
}

#[function_component(BreadcrumbItem)]
pub fn breadcrumb_item(props: &BreadcrumbItemProps) -> Html {
    html! {
        <li class="breadcrumb-item">
            {
                if let Some(path) = &props.path {
                    html! { <Link<Route> to={path.clone()}>{ &props.label }</Link<Route>> }
                } else {
                    html! { <span class="breadcrumb-current">{ &props.label }</span> }
                }
            }
        </li>
    }
}

// Props for the main Breadcrumb component
#[derive(Clone, PartialEq, Properties)]
pub struct BreadcrumbProps {
    #[prop_or_default]
    pub separator: Option<String>,
    // Potentially add a class prop if needed for styling
    // #[prop_or_default]
    // pub class: Classes,
}

// The main Breadcrumb component
#[function_component(Breadcrumb)]
pub fn breadcrumb(props: &BreadcrumbProps) -> Html {
    let route = use_route::<Route>();
    let separator = props.separator.clone().unwrap_or_else(|| "/".to_string());

    let items = if let Some(current_route) = route {
        generate_breadcrumbs(current_route)
    } else {
        Vec::new()
    };

    if items.is_empty() {
        return html! {}; // Don't render if there are no items (e.g., on home or if route is None)
    }

    html! {
        <nav aria-label="breadcrumb">
            <ol class="breadcrumb-list"> // Changed from <ul> to <ol> for semantic correctness
                {
                    items.into_iter().enumerate().map(|(i, item_props)| {
                        html! {
                            <>
                                <BreadcrumbItem label={item_props.label} path={item_props.path} />
                                { if i < items.len() - 1 { // Check if it's not the last item
                                    html!{ <span class="breadcrumb-separator">{separator.clone()}</span> }
                                  } else {
                                    html!{}
                                  }
                                }
                            </>
                        }
                    }).collect::<Html>()
                }
            </ol>
        </nav>
    }
}

// Helper function to generate breadcrumb items from the current route
// This is a basic implementation and will need to be more sophisticated
fn generate_breadcrumbs(route: Route) -> Vec<BreadcrumbItemProps> {
    let mut items = Vec::new();
    items.push(BreadcrumbItemProps { label: "Home".to_string(), path: Some(Route::Home) });

    match route {
        Route::Home => {
            // For home, only the "Home" breadcrumb is shown, or none if preferred.
            // Current logic will show "Home" then "Home" if we don't clear.
            items.pop(); // Remove the default "Home" if we are already there.
             items.push(BreadcrumbItemProps { label: "Home".to_string(), path: None }); // Current page, no link
        }
        Route::About => {
            items.push(BreadcrumbItemProps { label: "About".to_string(), path: None });
        }
        Route::Login => {
            items.push(BreadcrumbItemProps { label: "Login".to_string(), path: None });
        }
        Route::Dashboard => {
            items.push(BreadcrumbItemProps { label: "Dashboard".to_string(), path: None });
        }
        Route::Register => {
            items.push(BreadcrumbItemProps { label: "Register".to_string(), path: None });
        }
        Route::EmailVerified => {
             items.push(BreadcrumbItemProps { label: "Email Verified".to_string(), path: None });
        }
        Route::RegistrationComplete => {
            items.push(BreadcrumbItemProps { label: "Registration Complete".to_string(), path: None });
        }
        Route::PasswordResetRequest => {
            items.push(BreadcrumbItemProps { label: "Reset Password".to_string(), path: None });
        }
        Route::PasswordResetVerify => {
            items.push(BreadcrumbItemProps { label: "Reset Password".to_string(), path: Some(Route::PasswordResetRequest) });
            items.push(BreadcrumbItemProps { label: "Verify".to_string(), path: None });
        }
        Route::PasswordResetNew => {
            items.push(BreadcrumbItemProps { label: "Reset Password".to_string(), path: Some(Route::PasswordResetRequest) });
            items.push(BreadcrumbItemProps { label: "New Password".to_string(), path: None });
        }
        // For NotFound, we might not want a breadcrumb trail, or just "Home / 404"
        Route::NotFound => {
             items.push(BreadcrumbItemProps { label: "404 Not Found".to_string(), path: None });
        }
        // Default case, should ideally not be hit if all routes are covered
        _ => {
            // Potentially log an error or handle unknown routes
        }
    }
    // Filter out the Home link if it's the only item and it's also the current page
    if items.len() == 1 && items[0].path.is_none() && items[0].label == "Home" {
        return Vec::new();
    }

    items
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::Route;

    // Helper to create BreadcrumbItemProps for cleaner test assertions
    fn new_item(label: &str, path: Option<Route>) -> BreadcrumbItemProps {
        BreadcrumbItemProps {
            label: label.to_string(),
            path,
        }
    }

    #[test]
    fn test_generate_breadcrumbs_home() {
        let items = generate_breadcrumbs(Route::Home);
        // According to current logic: if current page is Home, and it's the only item, it's empty.
        assert!(items.is_empty(), "Breadcrumbs for Home route should be empty");
    }

    #[test]
    fn test_generate_breadcrumbs_about() {
        let items = generate_breadcrumbs(Route::About);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], new_item("Home", Some(Route::Home)));
        assert_eq!(items[1], new_item("About", None));
    }

    #[test]
    fn test_generate_breadcrumbs_login() {
        let items = generate_breadcrumbs(Route::Login);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], new_item("Home", Some(Route::Home)));
        assert_eq!(items[1], new_item("Login", None));
    }

    #[test]
    fn test_generate_breadcrumbs_dashboard() {
        let items = generate_breadcrumbs(Route::Dashboard);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], new_item("Home", Some(Route::Home)));
        assert_eq!(items[1], new_item("Dashboard", None));
    }

    #[test]
    fn test_generate_breadcrumbs_password_reset_request() {
        let items = generate_breadcrumbs(Route::PasswordResetRequest);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], new_item("Home", Some(Route::Home)));
        assert_eq!(items[1], new_item("Reset Password", None));
    }

    #[test]
    fn test_generate_breadcrumbs_password_reset_verify() {
        let items = generate_breadcrumbs(Route::PasswordResetVerify);
        assert_eq!(items.len(), 3);
        assert_eq!(items[0], new_item("Home", Some(Route::Home)));
        assert_eq!(items[1], new_item("Reset Password", Some(Route::PasswordResetRequest)));
        assert_eq!(items[2], new_item("Verify", None));
    }

    #[test]
    fn test_generate_breadcrumbs_password_reset_new() {
        let items = generate_breadcrumbs(Route::PasswordResetNew);
        assert_eq!(items.len(), 3);
        assert_eq!(items[0], new_item("Home", Some(Route::Home)));
        assert_eq!(items[1], new_item("Reset Password", Some(Route::PasswordResetRequest)));
        assert_eq!(items[2], new_item("New Password", None));
    }

    #[test]
    fn test_generate_breadcrumbs_not_found() {
        let items = generate_breadcrumbs(Route::NotFound);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], new_item("Home", Some(Route::Home)));
        assert_eq!(items[1], new_item("404 Not Found", None));
    }

    // Test a case where a route might not be explicitly handled by the match,
    // though ideally all variants of Route should be covered.
    // This test depends on how `_ => {}` is handled in generate_breadcrumbs.
    // Currently, it does nothing, so it would only have "Home".
    // For this example, let's assume a hypothetical `Route::SomeOther` if it existed
    // and was not in the match. The current code would return just "Home".
    // Since all routes are covered, this test is more of a thought exercise
    // unless a new route is added and not updated in breadcrumbs.
    // For now, we can skip such a test as all enum variants are handled.
}
