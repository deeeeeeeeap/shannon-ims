package notify

import "testing"

func TestBuildTelegramTextMessageKeepsRawSMSContent(t *testing.T) {
	t.Parallel()

	text := "📩 收到新短信\n内容: <#> 验证码 #123456 <b>TAG</b>"
	msg := buildTelegramTextMessage(12345, text)

	wantText := "📩 收到新短信\n内容: &lt;#&gt; 验证码 #123456 &lt;b&gt;TAG&lt;/b&gt;"
	if msg.Text != wantText {
		t.Fatalf("Text = %q, want %q", msg.Text, wantText)
	}
	if msg.ParseMode != "HTML" {
		t.Fatalf("ParseMode = %q, want HTML", msg.ParseMode)
	}
	if msg.ChatID != 12345 {
		t.Fatalf("ChatID = %d, want 12345", msg.ChatID)
	}
}

func TestUnknownCommandReplyUsesPlainTemplate(t *testing.T) {
	t.Parallel()

	got := unknownCommandReply("badcmd")
	want := "未知命令 / badcmd\n提示    请检查命令名或使用 /list、/status、/send 等已注册命令"
	if got != want {
		t.Fatalf("unknownCommandReply() = %q, want %q", got, want)
	}
}
