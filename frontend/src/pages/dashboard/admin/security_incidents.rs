use yew::prelude::*;
use std::collections::HashMap;

// Data structures
#[derive(Clone, PartialEq)]
pub struct SecurityIncident {
    id: String,
    timestamp: String,
    severity: IncidentSeverity,
    status: IncidentStatus,
    incident_type: String,
    description: String,
    affected_systems: Vec<String>,
    details: HashMap<String, String>,
}

#[derive(Clone, PartialEq)]
pub enum IncidentSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Clone, PartialEq)]
pub enum IncidentStatus {
    Open,
    InProgress,
    Resolved,
    Closed,
}

pub enum Msg {
    FilterBySeverity(IncidentSeverity),
    FilterByStatus(IncidentStatus),
    SelectIncident(usize),
    CloseModal,
    ApplyFilter(String),
}

pub struct SecurityIncidents {
    selected_severity: Option<IncidentSeverity>,
    selected_status: Option<IncidentStatus>,
    selected_incident: Option<usize>,
    filter_text: String,
    incidents: Vec<SecurityIncident>,
}

impl Component for SecurityIncidents {
    type Message = Msg;
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        Self {
            selected_severity: None,
            selected_status: None,
            selected_incident: None,
            filter_text: String::new(),
            incidents: get_mock_incidents(),
        }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Msg::FilterBySeverity(severity) => {
                self.selected_severity = Some(severity);
                true
            }
            Msg::FilterByStatus(status) => {
                self.selected_status = Some(status);
                true
            }
            Msg::SelectIncident(index) => {
                self.selected_incident = Some(index);
                true
            }
            Msg::CloseModal => {
                self.selected_incident = None;
                true
            }
            Msg::ApplyFilter(text) => {
                self.filter_text = text;
                true
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        html! {
            <div class="l-grid l-grid--dashboard">
                <div class="c-card c-card--dashboard">
                    <h2 class="c-card__title">{"Security Incidents"}</h2>
                    
                    // Filter Section
                    <div class="c-filters">
                        {self.render_filters(ctx)}
                    </div>

                    // Incidents Table
                    <div class="c-table-container">
                        {self.render_incidents_table(ctx)}
                    </div>

                    // Detail Modal
                    {self.render_detail_modal(ctx)}
                </div>
            </div>
        }
    }
}

impl SecurityIncidents {
    fn render_filters(&self, ctx: &Context<Self>) -> Html {
        let onchange = ctx.link().callback(|e: Event| {
            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
            Msg::ApplyFilter(input.value())
        });

        html! {
            <div class="c-filters__container">
                <input 
                    type="text"
                    class="c-filters__input"
                    placeholder="Search incidents..."
                    value={self.filter_text.clone()}
                    onchange={onchange}
                />
                <div class="c-filters__group">
                    {self.render_severity_filters(ctx)}
                    {self.render_status_filters(ctx)}
                </div>
            </div>
        }
    }

    fn render_severity_filters(&self, ctx: &Context<Self>) -> Html {
        let severities = vec![
            IncidentSeverity::Critical,
            IncidentSeverity::High,
            IncidentSeverity::Medium,
            IncidentSeverity::Low,
        ];

        html! {
            <div class="c-filters__buttons">
                {severities.iter().map(|severity| {
                    let severity_clone = severity.clone();
                    let onclick = ctx.link().callback(move |_| {
                        Msg::FilterBySeverity(severity_clone.clone())
                    });
                    
                    let active = self.selected_severity.as_ref().map_or(false, |s| s == severity);
                    let class = if active { "c-button--active" } else { "" };
                    
                    html! {
                        <button 
                            class={classes!("c-button", "c-button--filter", class)}
                            onclick={onclick}
                        >
                            {self.get_severity_label(severity)}
                        </button>
                    }
                }).collect::<Html>()}
            </div>
        }
    }

    fn render_status_filters(&self, ctx: &Context<Self>) -> Html {
        let statuses = vec![
            IncidentStatus::Open,
            IncidentStatus::InProgress,
            IncidentStatus::Resolved,
            IncidentStatus::Closed,
        ];

        html! {
            <div class="c-filters__buttons">
                {statuses.iter().map(|status| {
                    let status_clone = status.clone();
                    let onclick = ctx.link().callback(move |_| {
                        Msg::FilterByStatus(status_clone.clone())
                    });
                    
                    let active = self.selected_status.as_ref().map_or(false, |s| s == status);
                    let class = if active { "c-button--active" } else { "" };
                    
                    html! {
                        <button 
                            class={classes!("c-button", "c-button--filter", class)}
                            onclick={onclick}
                        >
                            {self.get_status_label(status)}
                        </button>
                    }
                }).collect::<Html>()}
            </div>
        }
    }

    fn render_incidents_table(&self, ctx: &Context<Self>) -> Html {
        let filtered_incidents = self.get_filtered_incidents();

        html! {
            <table class="c-table">
                <thead>
                    <tr>
                        <th>{"ID"}</th>
                        <th>{"Timestamp"}</th>
                        <th>{"Severity"}</th>
                        <th>{"Status"}</th>
                        <th>{"Type"}</th>
                        <th>{"Description"}</th>
                    </tr>
                </thead>
                <tbody>
                    {filtered_incidents.iter().enumerate().map(|(index, incident)| {
                        let onclick = ctx.link().callback(move |_| Msg::SelectIncident(index));
                        
                        html! {
                            <tr 
                                class={self.get_row_class(&incident.severity)}
                                onclick={onclick}
                            >
                                <td>{&incident.id}</td>
                                <td>{&incident.timestamp}</td>
                                <td>{self.get_severity_label(&incident.severity)}</td>
                                <td>{self.get_status_label(&incident.status)}</td>
                                <td>{&incident.incident_type}</td>
                                <td>{&incident.description}</td>
                            </tr>
                        }
                    }).collect::<Html>()}
                </tbody>
            </table>
        }
    }

    fn render_detail_modal(&self, ctx: &Context<Self>) -> Html {
        if let Some(index) = self.selected_incident {
            if let Some(incident) = self.incidents.get(index) {
                let overlay_close = ctx.link().callback(|_| Msg::CloseModal);
                let button_close = ctx.link().callback(|_| Msg::CloseModal);
                let footer_close = ctx.link().callback(|_| Msg::CloseModal);
                
                html! {
                    <div class="c-modal">
                        <div class="c-modal__overlay" onclick={overlay_close}></div>
                        <div class="c-modal__container" style="max-width: 650px; margin-top: 50px; padding: 0 20px;">
                            <div class="c-modal__header">
                                <h3 class="c-modal__title">{"Incident Details"}</h3>
                                <button 
                                    class="c-modal__close" 
                                    onclick={button_close}
                                    aria-label="Close"
                                >
                                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                        <line x1="18" y1="6" x2="6" y2="18"></line>
                                        <line x1="6" y1="6" x2="18" y2="18"></line>
                                    </svg>
                                </button>
                            
</div>
                            <div class="c-modal__body">
                                <div class="c-incident-detail">
                                    <div class="c-incident-detail__field">
                                        <div class="c-incident-detail__label" style="width: 120px;">{"ID:"}</div>
                                        <div class="c-incident-detail__value" style="display: inline-block; max-width: 400px;">{&incident.id}</div>
                                    </div>
                                    
                                    <div class="c-incident-detail__field">
                                        <div class="c-incident-detail__label" style="width: 120px;">{"Timestamp:"}</div>
                                        <div class="c-incident-detail__value" style="display: inline-block; max-width: 400px;">{&incident.timestamp}</div>
                                    </div>
                                    
                                    <div class="c-incident-detail__field">
                                        <div class="c-incident-detail__label" style="width: 120px;">{"Severity:"}</div>
                                        <div class={classes!("c-incident-detail__value", format!("c-incident-detail__value--{}", self.get_severity_class(&incident.severity)))} style="display: inline-block; max-width: 400px;">
                                            {self.get_severity_label(&incident.severity)}
                                        </div>
                                    </div>
                                    
                                    <div class="c-incident-detail__field">
                                        <div class="c-incident-detail__label" style="width: 120px;">{"Status:"}</div>
                                        <div class={classes!("c-incident-detail__value", format!("c-incident-detail__value--{}", self.get_status_class(&incident.status)))} style="display: inline-block; max-width: 400px;">
                                            {self.get_status_label(&incident.status)}
                                        </div>
                                    </div>
                                    
                                    <div class="c-incident-detail__field">
                                        <div class="c-incident-detail__label" style="width: 120px;">{"Type:"}</div>
                                        <div class="c-incident-detail__value" style="display: inline-block; max-width: 400px;">{&incident.incident_type}</div>
                                    </div>
                                    
                                    <div class="c-incident-detail__field">
                                        <div class="c-incident-detail__label" style="width: 120px;">{"Description:"}</div>
                                        <div class="c-incident-detail__value" style="display: inline-block; max-width: 400px;">{&incident.description}</div>
                                    </div>
                                </div>
                                
                                <div class="c-incident-detail__section">
                                    <h4 class="c-incident-detail__section-title">{"Affected Systems"}</h4>
                                    <ul>
                                        {incident.affected_systems.iter().map(|system| {
                                            html! { <li>{system}</li> }
                                        }).collect::<Html>()}
                                    </ul>
                                    
                                    <h4 class="c-incident-detail__section-title">{"Additional Details"}</h4>
                                    {self.render_incident_details(&incident.details)}
                                </div>
                            </div>
                            <div class="c-modal__footer">
                                <button 
                                    class="c-button c-button--secondary-user-detail c-button--user-detail" 
                                    onclick={footer_close}
                                >
                                    {"Close"}
                                </button>
                            </div>
                        </div>
                    </div>
                }
            } else {
                html! {}
            }
        } else {
            html! {}
        }
    }

    // Helper methods
    fn get_severity_label(&self, severity: &IncidentSeverity) -> &'static str {
        match severity {
            IncidentSeverity::Critical => "Critical",
            IncidentSeverity::High => "High",
            IncidentSeverity::Medium => "Medium",
            IncidentSeverity::Low => "Low",
        }
    }

    fn get_status_label(&self, status: &IncidentStatus) -> &'static str {
        match status {
            IncidentStatus::Open => "Open",
            IncidentStatus::InProgress => "In Progress",
            IncidentStatus::Resolved => "Resolved",
            IncidentStatus::Closed => "Closed",
        }
    }

    fn get_row_class(&self, severity: &IncidentSeverity) -> &'static str {
        match severity {
            IncidentSeverity::Critical => "c-table__row--critical",
            IncidentSeverity::High => "c-table__row--high",
            IncidentSeverity::Medium => "c-table__row--medium",
            IncidentSeverity::Low => "c-table__row--low",
        }
    }

    fn get_severity_class(&self, severity: &IncidentSeverity) -> &'static str {
        match severity {
            IncidentSeverity::Critical => "critical",
            IncidentSeverity::High => "high",
            IncidentSeverity::Medium => "medium",
            IncidentSeverity::Low => "low",
        }
    }

    fn get_status_class(&self, status: &IncidentStatus) -> &'static str {
        match status {
            IncidentStatus::Open => "open",
            IncidentStatus::InProgress => "in-progress",
            IncidentStatus::Resolved => "resolved",
            IncidentStatus::Closed => "closed",
        }
    }

    fn render_incident_details(&self, details: &HashMap<String, String>) -> Html {
        html! {
            <div class="c-incident-detail__list">
                {details.iter().map(|(key, value)| {
                    html! {
                        <div class="c-incident-detail__field">
                            <div class="c-incident-detail__label" style="width: 120px;">{format!("{}:", key)}</div>
                            <div class="c-incident-detail__value" style="display: inline-block; max-width: 400px;">{value}</div>
                        </div>
                    }
                }).collect::<Html>()}
            </div>
        }
    }

    fn get_filtered_incidents(&self) -> Vec<SecurityIncident> {
        self.incidents
            .iter()
            .filter(|incident| {
                // Filter by severity
                if let Some(ref selected_severity) = self.selected_severity {
                    if &incident.severity != selected_severity {
                        return false;
                    }
                }
                
                // Filter by status
                if let Some(ref selected_status) = self.selected_status {
                    if &incident.status != selected_status {
                        return false;
                    }
                }

                // Filter by search text
                if !self.filter_text.is_empty() {
                    let search_text = self.filter_text.to_lowercase();
                    return incident.description.to_lowercase().contains(&search_text) ||
                           incident.incident_type.to_lowercase().contains(&search_text) ||
                           incident.id.to_lowercase().contains(&search_text);
                }
                
                true
            })
            .cloned()
            .collect()
    }
}

// Mock data generation
fn get_mock_incidents() -> Vec<SecurityIncident> {
    let mut incidents = Vec::new();
    
    // Critical incident
    let mut critical_details = HashMap::new();
    critical_details.insert("IP Address".to_string(), "192.168.1.100".to_string());
    critical_details.insert("User Agent".to_string(), "Mozilla/5.0...".to_string());
    critical_details.insert("Attack Vector".to_string(), "SQL Injection".to_string());
    
    incidents.push(SecurityIncident {
        id: "SEC-001".to_string(),
        timestamp: "2025-02-05 21:15:00".to_string(),
        severity: IncidentSeverity::Critical,
        status: IncidentStatus::Open,
        incident_type: "Data Breach Attempt".to_string(),
        description: "Multiple SQL injection attempts detected on login endpoint".to_string(),
        affected_systems: vec!["Authentication Service".to_string(), "User Database".to_string()],
        details: critical_details,
    });

    // High severity incident
    let mut high_details = HashMap::new();
    high_details.insert("Failed Attempts".to_string(), "25".to_string());
    high_details.insert("Time Period".to_string(), "5 minutes".to_string());
    high_details.insert("Target Account".to_string(), "admin@example.com".to_string());
    
    incidents.push(SecurityIncident {
        id: "SEC-002".to_string(),
        timestamp: "2025-02-05 21:14:30".to_string(),
        severity: IncidentSeverity::High,
        status: IncidentStatus::InProgress,
        incident_type: "Brute Force Attack".to_string(),
        description: "Multiple failed login attempts detected from multiple IPs".to_string(),
        affected_systems: vec!["Authentication Service".to_string()],
        details: high_details,
    });

    // Medium severity incident
    let mut medium_details = HashMap::new();
    medium_details.insert("Certificate Expiry".to_string(), "7 days".to_string());
    medium_details.insert("Domain".to_string(), "api.example.com".to_string());
    
    incidents.push(SecurityIncident {
        id: "SEC-003".to_string(),
        timestamp: "2025-02-05 21:14:00".to_string(),
        severity: IncidentSeverity::Medium,
        status: IncidentStatus::Open,
        incident_type: "SSL Certificate Warning".to_string(),
        description: "SSL certificate approaching expiration date".to_string(),
        affected_systems: vec!["API Gateway".to_string()],
        details: medium_details,
    });

    // Low severity incident
    let mut low_details = HashMap::new();
    low_details.insert("Policy Update".to_string(), "Password complexity increased".to_string());
    low_details.insert("Affected Users".to_string(), "15".to_string());
    
    incidents.push(SecurityIncident {
        id: "SEC-004".to_string(),
        timestamp: "2025-02-05 21:13:30".to_string(),
        severity: IncidentSeverity::Low,
        status: IncidentStatus::Resolved,
        incident_type: "Policy Violation".to_string(),
        description: "Users identified with weak passwords".to_string(),
        affected_systems: vec!["User Management".to_string()],
        details: low_details,
    });

    incidents
}
