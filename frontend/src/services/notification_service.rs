// frontend/src/services/notification_service.rs
use std::collections::VecDeque;
use crate::components::notifications::toast::ToastNotification;

#[derive(Debug, Default)]
pub struct NotificationService {
    toasts: VecDeque<ToastNotification>,
    next_id: usize,
    // In a Yew app, this service would likely use Agents/Contexts
    // to communicate with components and trigger re-renders.
}

impl NotificationService {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_toast(&mut self, toast: ToastNotification) {
        let mut toast_with_id = toast;
        toast_with_id.id = self.next_id;
        self.next_id += 1;
        self.toasts.push_back(toast_with_id);
        // Here you might trigger a state update for subscribers
    }

    pub fn remove_toast(&mut self, id: usize) -> Option<ToastNotification> {
        if let Some(index) = self.toasts.iter().position(|t| t.id == id) {
            self.toasts.remove(index)
        } else {
            None
        }
    }

    pub fn get_toasts(&self) -> &VecDeque<ToastNotification> {
        &self.toasts
    }

    // Auto-dismiss logic would typically be handled by the UI component itself
    // using timers, but the service could provide default durations or manage expirations.
}

// Basic tests for the service logic (not Yew component tests)
#[cfg(test)]
mod tests {
    use super::*;
    use crate::components::notifications::toast::{NotificationType, ToastPosition};

    #[test]
    fn test_add_toast() {
        let mut service = NotificationService::new();
        let toast = ToastNotification {
            id: 0, // Initial ID, will be overridden
            message: "Test success".to_string(),
            notification_type: NotificationType::Success,
            duration_ms: 3000,
            position: ToastPosition::TopRight,
        };
        service.add_toast(toast.clone());
        assert_eq!(service.get_toasts().len(), 1);
        assert_eq!(service.get_toasts()[0].message, "Test success");
        assert_eq!(service.get_toasts()[0].id, 0); // First ID is 0
    }

    #[test]
    fn test_remove_toast() {
        let mut service = NotificationService::new();
        let toast1 = ToastNotification {
            id: 0, message: "Toast 1".to_string(), notification_type: NotificationType::Info,
            duration_ms: 3000, position: ToastPosition::TopCenter
        };
        let toast2 = ToastNotification {
            id: 0, message: "Toast 2".to_string(), notification_type: NotificationType::Warning,
            duration_ms: 5000, position: ToastPosition::BottomCenter
        };

        service.add_toast(toast1); // id will be 0
        service.add_toast(toast2); // id will be 1

        assert_eq!(service.get_toasts().len(), 2);

        let removed = service.remove_toast(0);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().message, "Toast 1");
        assert_eq!(service.get_toasts().len(), 1);
        assert_eq!(service.get_toasts()[0].id, 1); // Remaining toast has id 1

        let not_found = service.remove_toast(99); // Non-existent ID
        assert!(not_found.is_none());
        assert_eq!(service.get_toasts().len(), 1);
    }

    #[test]
    fn test_toast_ids_increment() {
        let mut service = NotificationService::new();
        for i in 0..5 {
            let toast = ToastNotification {
                id: 0, message: format!("Toast {}", i), notification_type: NotificationType::Info,
                duration_ms: 1000, position: ToastPosition::Center
            };
            service.add_toast(toast);
        }
        let toasts = service.get_toasts();
        for i in 0..5 {
            assert_eq!(toasts[i].id, i);
        }
    }
}
