// frontend/src/components/notifications/toast.rs

#[derive(Debug, Clone, PartialEq)]
pub enum NotificationType {
    Success,
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ToastPosition {
    TopLeft,
    TopCenter,
    TopRight,
    BottomLeft,
    BottomCenter,
    BottomRight,
    Center,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ToastNotification {
    pub id: usize, // Simple ID generation, could be UUID in a real app
    pub message: String,
    pub notification_type: NotificationType,
    pub duration_ms: u32, // Duration in milliseconds
    pub position: ToastPosition,
    // In a real Yew component, you'd have rendering logic here
    // and potentially callbacks for on_close, etc.
}

// Example function to create a toast - in a real app, this might be part of a service
pub fn create_toast(
    id: usize,
    message: String,
    notification_type: NotificationType,
    duration_ms: u32,
    position: ToastPosition,
) -> ToastNotification {
    ToastNotification {
        id,
        message,
        notification_type,
        duration_ms,
        position,
    }
}
