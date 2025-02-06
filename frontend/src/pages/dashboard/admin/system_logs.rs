use yew::prelude::*;
use std::collections::HashMap;

// Mock data structures
#[derive(Clone, PartialEq)]
pub struct LogEntry {
    timestamp: String,
    severity: LogSeverity,
    source: String,
    message: String,
    details: HashMap<String, String>,
}

#[derive(Clone, PartialEq)]
pub enum LogSeverity {
    Error,
    Warning,
    Info,
    Security,
    Performance,
}

#[derive(Clone, PartialEq)]
pub enum LogCategory {
    Error,
    Warning,
    Info,
    Security,
    Performance,
}

pub enum Msg {
    SwitchCategory(LogCategory),
    SelectLogEntry(usize),
    CloseModal,
    ApplyFilter(String),
}

pub struct SystemLogs {
    selected_category: LogCategory,
    selected_entry: Option<usize>,
    filter_text: String,
    logs: Vec<LogEntry>,
}

impl Component for SystemLogs {
    type Message = Msg;
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        Self {
            selected_category: LogCategory::Error,
            selected_entry: None,
            filter_text: String::new(),
            logs: get_mock_logs(), // Initialize with mock data
        }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Msg::SwitchCategory(category) => {
                self.selected_category = category;
                true
            }
            Msg::SelectLogEntry(index) => {
                self.selected_entry = Some(index);
                true
            }
            Msg::CloseModal => {
                self.selected_entry = None;
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
                    <h2 class="c-card__title">{"System Logs"}</h2>
                    
                    // Tab Navigation
                    <div class="c-tabs">
                        {self.render_category_tabs(ctx)}
                    </div>

                    // Filter Section
                    <div class="c-filters">
                        {self.render_filters(ctx)}
                    </div>

                    // Log Table
                    <div class="c-table-container">
                        {self.render_log_table(ctx)}
                    </div>

                    // Detail Modal
                    {self.render_detail_modal(ctx)}
                </div>
            </div>
        }
    }
}

impl SystemLogs {
    fn render_category_tabs(&self, ctx: &Context<Self>) -> Html {
        let categories = vec![
            LogCategory::Error,
            LogCategory::Warning,
            LogCategory::Info,
            LogCategory::Security,
            LogCategory::Performance,
        ];

        html! {
            <div class="c-tabs__list">
                {categories.iter().map(|category| {
                    let category_clone = category.clone();
                    let onclick = ctx.link().callback(move |_| {
                        Msg::SwitchCategory(category_clone.clone())
                    });
                    
                    let active_class = if self.selected_category == *category {
                        "c-tabs__tab--active"
                    } else {
                        ""
                    };

                    html! {
                        <button 
                            class={classes!("c-tabs__tab", active_class)}
                            onclick={onclick}
                        >
                            {self.get_category_label(category)}
                        </button>
                    }
                }).collect::<Html>()}
            </div>
        }
    }

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
                    placeholder="Filter logs..."
                    value={self.filter_text.clone()}
                    onchange={onchange}
                />
                <div class="c-filters__date">
                    // Date range picker placeholder
                    <span>{"Date Range (Coming Soon)"}</span>
                </div>
            </div>
        }
    }

    fn render_log_table(&self, ctx: &Context<Self>) -> Html {
        let filtered_logs = self.get_filtered_logs();

        html! {
            <table class="c-table">
                <thead>
                    {self.render_table_header()}
                </thead>
                <tbody>
                    {filtered_logs.iter().enumerate().map(|(index, log)| {
                        let onclick = ctx.link().callback(move |_| Msg::SelectLogEntry(index));
                        
                        html! {
                            <tr 
                                class={self.get_row_class(&log.severity)}
                                onclick={onclick}
                            >
                                <td>{&log.timestamp}</td>
                                <td>{self.get_severity_label(&log.severity)}</td>
                                <td>{&log.source}</td>
                                <td>{&log.message}</td>
                            </tr>
                        }
                    }).collect::<Html>()}
                </tbody>
            </table>
        }
    }

    fn render_detail_modal(&self, ctx: &Context<Self>) -> Html {
        if let Some(index) = self.selected_entry {
            if let Some(log) = self.logs.get(index) {
                let onclose = ctx.link().callback(|_| Msg::CloseModal);
                
                html! {
                    <div class="c-modal">
                        <div class="c-modal__content">
                            <button class="c-modal__close" onclick={onclose}>{"×"}</button>
                            <h3 class="c-modal__title">{"Log Details"}</h3>
                            
                            <div class="c-modal__body">
                                <p><strong>{"Timestamp: "}</strong>{&log.timestamp}</p>
                                <p><strong>{"Severity: "}</strong>{self.get_severity_label(&log.severity)}</p>
                                <p><strong>{"Source: "}</strong>{&log.source}</p>
                                <p><strong>{"Message: "}</strong>{&log.message}</p>
                                
                                <div class="c-modal__details">
                                    <h4>{"Additional Details"}</h4>
                                    {self.render_log_details(&log.details)}
                                </div>
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
    fn get_category_label(&self, category: &LogCategory) -> &'static str {
        match category {
            LogCategory::Error => "Errors",
            LogCategory::Warning => "Warnings",
            LogCategory::Info => "Information",
            LogCategory::Security => "Security",
            LogCategory::Performance => "Performance",
        }
    }

    fn get_severity_label(&self, severity: &LogSeverity) -> &'static str {
        match severity {
            LogSeverity::Error => "Error",
            LogSeverity::Warning => "Warning",
            LogSeverity::Info => "Info",
            LogSeverity::Security => "Security",
            LogSeverity::Performance => "Performance",
        }
    }

    fn get_row_class(&self, severity: &LogSeverity) -> &'static str {
        match severity {
            LogSeverity::Error => "c-table__row--error",
            LogSeverity::Warning => "c-table__row--warning",
            LogSeverity::Info => "c-table__row--info",
            LogSeverity::Security => "c-table__row--security",
            LogSeverity::Performance => "c-table__row--performance",
        }
    }

    fn render_table_header(&self) -> Html {
        html! {
            <tr>
                <th>{"Timestamp"}</th>
                <th>{"Severity"}</th>
                <th>{"Source"}</th>
                <th>{"Message"}</th>
            </tr>
        }
    }

    fn render_log_details(&self, details: &HashMap<String, String>) -> Html {
        html! {
            <div class="c-modal__details-list">
                {details.iter().map(|(key, value)| {
                    html! {
                        <div class="c-modal__details-item">
                            <strong>{format!("{}: ", key)}</strong>
                            <span>{value}</span>
                        </div>
                    }
                }).collect::<Html>()}
            </div>
        }
    }

    fn get_filtered_logs(&self) -> Vec<LogEntry> {
        self.logs
            .iter()
            .filter(|log| {
                // Filter by category
                match self.selected_category {
                    LogCategory::Error => matches!(log.severity, LogSeverity::Error),
                    LogCategory::Warning => matches!(log.severity, LogSeverity::Warning),
                    LogCategory::Info => matches!(log.severity, LogSeverity::Info),
                    LogCategory::Security => matches!(log.severity, LogSeverity::Security),
                    LogCategory::Performance => matches!(log.severity, LogSeverity::Performance),
                }
            })
            .filter(|log| {
                // Filter by search text
                if self.filter_text.is_empty() {
                    return true;
                }
                let search_text = self.filter_text.to_lowercase();
                log.message.to_lowercase().contains(&search_text) ||
                log.source.to_lowercase().contains(&search_text)
            })
            .cloned()
            .collect()
    }
}

// Mock data generation
fn get_mock_logs() -> Vec<LogEntry> {
    let mut logs = Vec::new();
    
    // Add some mock error logs
    let mut error_details = HashMap::new();
    error_details.insert("Stack Trace".to_string(), "Error at line 42: NullPointerException".to_string());
    error_details.insert("Error Code".to_string(), "E404".to_string());
    
    logs.push(LogEntry {
        timestamp: "2025-02-05 21:15:00".to_string(),
        severity: LogSeverity::Error,
        source: "Authentication Service".to_string(),
        message: "Failed to validate user token".to_string(),
        details: error_details,
    });

    // Add some mock warning logs
    let mut warning_details = HashMap::new();
    warning_details.insert("Impact".to_string(), "Medium".to_string());
    warning_details.insert("Affected Users".to_string(), "5".to_string());
    
    logs.push(LogEntry {
        timestamp: "2025-02-05 21:14:30".to_string(),
        severity: LogSeverity::Warning,
        source: "Database Service".to_string(),
        message: "High memory usage detected".to_string(),
        details: warning_details,
    });

    // Add mock info logs
    let mut info_details = HashMap::new();
    info_details.insert("User ID".to_string(), "user123".to_string());
    info_details.insert("Session ID".to_string(), "sess_abc123".to_string());
    
    logs.push(LogEntry {
        timestamp: "2025-02-05 21:14:00".to_string(),
        severity: LogSeverity::Info,
        source: "User Service".to_string(),
        message: "User logged in successfully".to_string(),
        details: info_details,
    });

    // Add mock security logs
    let mut security_details = HashMap::new();
    security_details.insert("IP Address".to_string(), "192.168.1.100".to_string());
    security_details.insert("Location".to_string(), "New York, USA".to_string());
    
    logs.push(LogEntry {
        timestamp: "2025-02-05 21:13:30".to_string(),
        severity: LogSeverity::Security,
        source: "Security Service".to_string(),
        message: "Multiple failed login attempts detected".to_string(),
        details: security_details,
    });

    // Add mock performance logs
    let mut performance_details = HashMap::new();
    performance_details.insert("CPU Usage".to_string(), "85%".to_string());
    performance_details.insert("Memory Usage".to_string(), "2.5GB".to_string());
    performance_details.insert("Disk I/O".to_string(), "150MB/s".to_string());
    
    logs.push(LogEntry {
        timestamp: "2025-02-05 21:13:00".to_string(),
        severity: LogSeverity::Performance,
        source: "System Monitor".to_string(),
        message: "High CPU utilization".to_string(),
        details: performance_details,
    });

    logs
}
