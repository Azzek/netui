use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    style::Style,
    text::Text,
    widgets::{Block, Paragraph},
};

use crate::{app::App, ui::components::popup::Popup};

pub fn render_ui(frame: &mut Frame, app: &App) {
    let layout = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Percentage(10),
            Constraint::Percentage(80),
            Constraint::Percentage(10),
        ])
        .split(frame.area());

    let header = Paragraph::new(Text::raw("[1] Main page | [2] Scan ports")).block(
        Block::bordered()
            .border_type(ratatui::widgets::BorderType::Rounded)
            .border_style(Style::new().blue()),
    );
    let footer = Paragraph::new(Text::raw("[H-help] [Q-Quit] [<- left] [right ->]"))
        .centered()
        .block(
            Block::bordered()
                .border_type(ratatui::widgets::BorderType::Rounded)
                .border_style(Style::new().blue()),
        );
    frame.render_widget(header, layout[0]);
    app.current_page().render(frame, layout[1], &app);
    frame.render_widget(footer, layout[2]);

    if let Some(ref txt) = app.popup {
        let popup = Popup::new(txt.to_string());
        frame.render_widget(popup, frame.area());
    }
}
