#include <QtWidgets>
#include <QtNetwork>
#include <algorithm>
#include <optional>
#include <memory>
#include <cstdio>
#ifdef Q_OS_WIN
#include <windows.h>
#include <wincrypt.h>
#endif

namespace {
QString dataDirectory() {
    return QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
}
QString freshId() { return QUuid::createUuid().toString(QUuid::WithoutBraces); }

struct Profile {
    QString id = freshId(), name, host, user, key, secret, protectedSecret;
    QString bind = "127.0.0.1", localHost = "127.0.0.1";
    int sshPort = 22, remotePort = 2222, localPort = 1111;
    bool remember = false;
    QJsonObject json() const {
        return {{"id", id}, {"name", name}, {"host", host}, {"user", user},
                {"key", key}, {"protectedSecret", protectedSecret}, {"bind", bind},
                {"localHost", localHost}, {"sshPort", sshPort},
                {"remotePort", remotePort}, {"localPort", localPort}, {"remember", remember}};
    }
    static Profile fromJson(const QJsonObject &o) {
        Profile p;
        p.id = o.value("id").toString(p.id); p.name = o.value("name").toString();
        p.host = o.value("host").toString(); p.user = o.value("user").toString();
        p.key = o.value("key").toString(); p.protectedSecret = o.value("protectedSecret").toString();
        p.bind = o.value("bind").toString("127.0.0.1");
        p.localHost = o.value("localHost").toString("127.0.0.1");
        p.sshPort = o.value("sshPort").toInt(22);
        p.remotePort = o.value("remotePort").toInt(2222);
        p.localPort = o.value("localPort").toInt(1111);
        p.remember = o.value("remember").toBool();
        return p;
    }
};

bool validHost(QString h) {
    if (h.startsWith('[') && h.endsWith(']')) h = h.mid(1, h.size()-2);
    if (h.isEmpty() || h.startsWith('-')) return false;
    QHostAddress address;
    if (address.setAddress(h)) return true;
    static const QRegularExpression dns("^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,252}$");
    return dns.match(h).hasMatch();
}
QString unbracket(QString s) {
    if (s.startsWith('[') && s.endsWith(']')) return s.mid(1, s.size()-2);
    return s;
}
QString forwardingHost(QString s) {
    s = unbracket(s);
    return s.contains(':') ? '[' + s + ']' : s;
}
QString validate(const Profile &p) {
    if (p.name.trimmed().isEmpty()) return "Enter a profile name.";
    if (!validHost(p.host) || !validHost(p.localHost) || !validHost(p.bind))
        return "Invalid server, local host or bind address. Use DNS, IPv4 or IPv6.";
    static const QRegularExpression user("^[a-zA-Z0-9_][a-zA-Z0-9_.@-]{0,127}$");
    if (!user.match(p.user).hasMatch()) return "Enter a valid SSH username.";
    for (int port : {p.sshPort, p.remotePort, p.localPort})
        if (port < 1 || port > 65535) return "Ports must be between 1 and 65535.";
    if (!p.key.isEmpty() && (!QFileInfo(p.key).isFile() || p.key.contains('\n')))
        return "Private key file not found.";
    if (p.secret.contains('\n') || p.secret.contains('\r') || p.secret.contains(QChar::Null))
        return "Password cannot contain a newline or NUL.";
    return {};
}

std::optional<QString> protect(const QString &plain) {
    if (plain.isEmpty()) return QString();
#ifdef Q_OS_WIN
    QByteArray bytes = plain.toUtf8();
    DATA_BLOB input{DWORD(bytes.size()), reinterpret_cast<BYTE *>(bytes.data())}, output{};
    if (!CryptProtectData(&input, L"VoidTunnel", nullptr, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN, &output)) return std::nullopt;
    QByteArray encrypted(reinterpret_cast<const char *>(output.pbData), int(output.cbData));
    SecureZeroMemory(output.pbData, output.cbData); LocalFree(output.pbData);
    bytes.fill('\0');
    return QString::fromLatin1(encrypted.toBase64());
#else
    return std::nullopt;
#endif
}
std::optional<QString> unprotect(const QString &encoded) {
    if (encoded.isEmpty()) return QString();
#ifdef Q_OS_WIN
    QByteArray bytes = QByteArray::fromBase64(encoded.toLatin1());
    DATA_BLOB input{DWORD(bytes.size()), reinterpret_cast<BYTE *>(bytes.data())}, output{};
    if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN, &output)) return std::nullopt;
    QString plain = QString::fromUtf8(reinterpret_cast<const char *>(output.pbData), int(output.cbData));
    SecureZeroMemory(output.pbData, output.cbData); LocalFree(output.pbData);
    return plain;
#else
    return std::nullopt;
#endif
}

QStringList sshArguments(const Profile &p, const QString &knownHosts) {
    QString kh = QDir::fromNativeSeparators(knownHosts);
    kh.replace('"', "\\\"");
    QStringList a{"-F", "none", "-N", "-T", "-v", "-p", QString::number(p.sshPort),
                  "-l", p.user, "-o", "StrictHostKeyChecking=accept-new",
                  "-o", "UserKnownHostsFile=\"" + kh + "\"",
                  "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=15",
                  "-o", "ServerAliveCountMax=3", "-o", "ConnectTimeout=12",
                  "-o", "ConnectionAttempts=1", "-o", "NumberOfPasswordPrompts=1",
                  "-o", "TCPKeepAlive=yes", "-o", "BatchMode=no",
                  "-o", "UpdateHostKeys=no", "-o", "ForwardAgent=no",
                  "-o", "PermitLocalCommand=no", "-o", "ControlMaster=no"};
    if (!p.key.isEmpty()) a << "-i" << p.key << "-o" << "IdentitiesOnly=yes";
    a << "-R" << QString("%1:%2:%3:%4").arg(forwardingHost(p.bind))
                    .arg(p.remotePort).arg(forwardingHost(p.localHost)).arg(p.localPort);
    a << unbracket(p.host);
    return a;
}

// SSH invokes this same executable as SSH_ASKPASS. No secret travels in argv/env.
int askpass() {
    const QString prompt = QCoreApplication::arguments().mid(1).join(' ');
    if (!prompt.contains("password", Qt::CaseInsensitive) &&
        !prompt.contains("passphrase", Qt::CaseInsensitive)) return 1;
    QLocalSocket socket;
    socket.connectToServer(qEnvironmentVariable("VOIDTUNNEL_PIPE"));
    if (!socket.waitForConnected(3000)) return 1;
    QByteArray request = qgetenv("VOIDTUNNEL_TOKEN") + '\n';
    if (socket.write(request) != request.size()) return 1;
    if (socket.bytesToWrite() > 0 && !socket.waitForBytesWritten(3000)) return 1;
    QByteArray response;
    QElapsedTimer timer; timer.start();
    while (!response.contains('\n') && timer.elapsed() < 5000) {
        if (socket.bytesAvailable() == 0 && !socket.waitForReadyRead(500)) {
            if (socket.state() == QLocalSocket::UnconnectedState) break;
        }
        response += socket.readAll();
        if (response.size() > 65536) return 1;
    }
    if (!response.contains('\n')) return 1;
    QJsonObject o = QJsonDocument::fromJson(response.trimmed()).object();
    if (!o.value("ok").toBool()) return 1;
    QByteArray answer = o.value("secret").toString().toUtf8() + '\n';
    bool ok = false;
#ifdef Q_OS_WIN
    DWORD written = 0;
    ok = WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), answer.constData(), DWORD(answer.size()), &written, nullptr)
         && written == DWORD(answer.size());
#else
    ok = fwrite(answer.constData(), 1, size_t(answer.size()), stdout) == size_t(answer.size());
    fflush(stdout);
#endif
    answer.fill('\0'); response.fill('\0');
    return ok ? 0 : 1;
}
}

class Tunnel : public QObject {
    Q_OBJECT
public:
    explicit Tunnel(QObject *parent = nullptr) : QObject(parent) {
        retry.setSingleShot(true); watchdog.setSingleShot(true);
#ifdef Q_OS_WIN
        process.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments *args) {
            args->flags |= CREATE_NO_WINDOW;
        });
#endif
        connect(&retry, &QTimer::timeout, this, &Tunnel::launch);
        connect(&watchdog, &QTimer::timeout, this, [this] {
            emit log("Connection timed out. Restarting SSH.");
            process.kill();
        });
        connect(&process, &QProcess::started, this, [this] {
            process.closeWriteChannel(); // askpass is the only authentication input
            watchdog.start(45000);
        });
        connect(&process, &QProcess::readyReadStandardError, this, [this] {
            pending += process.readAllStandardError();
            while (pending.contains('\n')) {
                int n = pending.indexOf('\n');
                QString line = QString::fromUtf8(pending.left(n)).trimmed();
                pending.remove(0, n+1); handleLine(line);
            }
            if (pending.size() > 65536) pending.clear();
        });
        connect(&process, &QProcess::readyReadStandardOutput, this, [this] {
            process.readAllStandardOutput();
        });
        connect(&process, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
                [this](int code, QProcess::ExitStatus) {
            watchdog.stop();
            if (!pending.isEmpty()) handleLine(QString::fromUtf8(pending));
            pending.clear(); server.close();
            emit log(QString("SSH exited with code %1.").arg(code));
            if (wanted) schedule(); else emit state("Disconnected", false);
        });
        connect(&process, &QProcess::errorOccurred, this, [this](QProcess::ProcessError e) {
            if (e == QProcess::FailedToStart) {
                watchdog.stop(); server.close(); wanted = false;
                emit log("Could not start OpenSSH: " + process.errorString());
                emit state("SSH error", false); emit stopped();
            }
        });
        server.setSocketOptions(QLocalServer::UserAccessOption);
        connect(&server, &QLocalServer::newConnection, this, [this] {
            while (server.hasPendingConnections()) {
                QLocalSocket *s = server.nextPendingConnection();
                auto buffer = std::make_shared<QByteArray>();
                auto done = std::make_shared<bool>(false);
                auto respond = [this, s, buffer, done] {
                    if (*done) return;
                    *buffer += s->readAll();
                    if (buffer->size() > 256) { *done = true; s->abort(); return; }
                    if (!buffer->contains('\n')) return;
                    *done = true;
                    bool ok = buffer->trimmed() == token.toUtf8() && wanted && !profile.secret.isEmpty();
                    QJsonObject response{{"ok", ok}};
                    if (ok) response.insert("secret", profile.secret);
                    s->write(QJsonDocument(response).toJson(QJsonDocument::Compact) + '\n');
                    s->disconnectFromServer();
                };
                connect(s, &QLocalSocket::readyRead, s, respond);
                connect(s, &QLocalSocket::disconnected, s, &QObject::deleteLater);
                QTimer::singleShot(6000, s, [s] { s->abort(); s->deleteLater(); });
                respond();
            }
        });
    }
    ~Tunnel() override {
        wanted = false; retry.stop(); process.kill(); process.waitForFinished(3000);
    }
    bool active() const { return wanted || process.state() != QProcess::NotRunning; }
    void start(const Profile &p) {
        if (active()) return;
        profile = p; wanted = true; attempts = 0; launch();
    }
    void stop() {
        wanted = false; retry.stop(); watchdog.stop(); server.close();
        if (process.state() != QProcess::NotRunning) {
            emit state("Stopping", false);
            // ssh -N has no remote command; killing closes sockets and remote listeners.
            process.kill();
        } else emit state("Disconnected", false);
        profile.secret.fill(QChar::Null); profile.secret.clear();
        emit stopped();
    }
signals:
    void log(const QString &text);
    void state(const QString &text, bool online);
    void stopped();
private:
    QProcess process;
    QLocalServer server;
    QTimer retry, watchdog;
    Profile profile;
    QString token;
    QByteArray pending;
    bool wanted = false;
    int attempts = 0;
    void handleLine(QString line) {
        if (line.isEmpty()) return;
        if (line.contains("remote forward success for:")) {
            watchdog.stop(); attempts = 0;
            emit state("Connected", true);
        }
        // Avoid displaying a literal secret even if it appears in an unusual server banner.
        if (!profile.secret.isEmpty()) line.replace(profile.secret, "[REDACTED]");
        emit log(line);
    }
    void schedule() {
        int delay = std::min(30, 1 << std::min(attempts++, 5));
        delay = delay * 1000 + int(QRandomGenerator::global()->bounded(500u));
        emit state(QString("Retry in %1 s").arg(delay/1000.0, 0, 'f', 1), false);
        emit log("Reconnecting with backoff (up to 30.5 s).");
        retry.start(delay);
    }
    void launch() {
        if (!wanted) return;
        const QString program = QStandardPaths::findExecutable("ssh");
        if (program.isEmpty()) {
            wanted = false; emit state("SSH not found", false);
            emit log("Install Windows OpenSSH Client and restart VoidTunnel.");
            emit stopped(); return;
        }
        server.close(); token = freshId() + freshId();
        QString pipe = "VoidTunnel-" + freshId();
        if (!server.listen(pipe)) {
            wanted = false; emit state("IPC error", false);
            emit log(server.errorString()); emit stopped(); return;
        }
        QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
        env.insert("SSH_ASKPASS", QCoreApplication::applicationFilePath());
        env.insert("SSH_ASKPASS_REQUIRE", "force"); env.insert("DISPLAY", "VoidTunnel:0");
        env.insert("VOIDTUNNEL_ASKPASS", "1"); env.insert("VOIDTUNNEL_PIPE", pipe);
        env.insert("VOIDTUNNEL_TOKEN", token); env.insert("LC_ALL", "C");
        process.setProcessEnvironment(env);
        process.setProgram(program);
        process.setArguments(sshArguments(profile, dataDirectory() + "/known_hosts"));
        pending.clear(); emit state("Connecting", false);
        emit log(QString("%1@%2:%3 // %4:%5 → %6:%7")
                 .arg(profile.user, profile.host).arg(profile.sshPort)
                 .arg(profile.bind).arg(profile.remotePort).arg(profile.localHost).arg(profile.localPort));
        process.start();
    }
};

class Window : public QMainWindow {
    Q_OBJECT
public:
    Window() {
        setWindowTitle("VoidTunnel"); resize(660, 370);
        setMinimumSize(620, 350);
        auto *root = new QWidget; setCentralWidget(root);
        auto *outer = new QVBoxLayout(root);
        outer->setContentsMargins(12, 12, 12, 12); outer->setSpacing(10);
        auto *head = new QHBoxLayout;
        auto *title = new QLabel("VoidTunnel"); title->setObjectName("brand");
        head->addWidget(title); head->addStretch();
        badge = new QLabel("Disconnected"); badge->setObjectName("badge"); head->addWidget(badge);
        outer->addLayout(head);
        auto *body = new QHBoxLayout; body->setSpacing(12); outer->addLayout(body, 1);
        auto *left = new QWidget; left->setFixedWidth(145);
        auto *ll = new QVBoxLayout(left); ll->setContentsMargins(0, 0, 0, 0); ll->setSpacing(6);
        ll->addWidget(new QLabel("Servers"));
        nodes = new QListWidget; ll->addWidget(nodes, 1);
        auto *nodeButtons = new QHBoxLayout;
        auto *add = new QPushButton("Add"); auto *del = new QPushButton("Remove");
        del->setObjectName("danger"); nodeButtons->addWidget(add); nodeButtons->addWidget(del);
        ll->addLayout(nodeButtons); body->addWidget(left);
        auto *right = new QVBoxLayout; right->setSpacing(6); body->addLayout(right, 1);
        editor = new QWidget;
        auto *editLayout = new QVBoxLayout(editor); editLayout->setContentsMargins(0, 0, 0, 0); editLayout->setSpacing(6);
        auto *form = new QFormLayout; form->setHorizontalSpacing(10); form->setVerticalSpacing(6);
        name = new QLineEdit; name->setPlaceholderText("My VPS");
        connection = new QLineEdit; connection->setPlaceholderText("user@host");
        sshPort = portSpin(22); remotePort = portSpin(2222); localPort = portSpin(1111);
        secret = new QLineEdit; secret->setEchoMode(QLineEdit::Password);
        secret->setPlaceholderText("Password or key passphrase");
        form->addRow("Name", name); form->addRow("Server", connection);
        form->addRow("SSH port", sshPort); form->addRow("Password", secret);
        auto *ports = new QWidget; auto *pr = new QHBoxLayout(ports); pr->setContentsMargins(0,0,0,0); pr->setSpacing(6);
        pr->addWidget(remotePort); pr->addWidget(new QLabel("to local")); pr->addWidget(localPort);
        remotePort->setToolTip("Listening port on the SSH server");
        localPort->setToolTip("Destination port on this computer");
        form->addRow("Remote port", ports); editLayout->addLayout(form);
        auto *advancedToggle = new QToolButton;
        advancedToggle->setText("Advanced"); advancedToggle->setCheckable(true);
        advancedToggle->setToolButtonStyle(Qt::ToolButtonTextBesideIcon); advancedToggle->setArrowType(Qt::RightArrow);
        editLayout->addWidget(advancedToggle);
        auto *advanced = new QWidget; advanced->hide();
        auto *af = new QFormLayout(advanced); af->setContentsMargins(0, 0, 0, 0);
        af->setHorizontalSpacing(10); af->setVerticalSpacing(6);
        key = new QLineEdit; key->setPlaceholderText("Optional; otherwise password or ssh-agent");
        auto *keyRow = new QWidget; auto *kr = new QHBoxLayout(keyRow); kr->setContentsMargins(0,0,0,0); kr->setSpacing(6);
        kr->addWidget(key); auto *browse = new QPushButton("..."); browse->setFixedWidth(30); kr->addWidget(browse);
        remember = new QCheckBox("Remember password (Windows DPAPI)");
#ifndef Q_OS_WIN
        remember->setEnabled(false); remember->setToolTip("Password storage is available on Windows only");
#endif
        bind = new QLineEdit("127.0.0.1"); localHost = new QLineEdit("127.0.0.1");
        bind->setToolTip("127.0.0.1: server-only access. 0.0.0.0: public access if sshd allows it.");
        af->addRow("Key file", keyRow); af->addRow("Bind address", bind); af->addRow("Local host", localHost);
        af->addRow("", remember); editLayout->addWidget(advanced);
        connect(advancedToggle, &QToolButton::toggled, this, [this, advanced, advancedToggle](bool expanded) {
            advanced->setVisible(expanded); advancedToggle->setArrowType(expanded ? Qt::DownArrow : Qt::RightArrow);
            QTimer::singleShot(0, this, [this] { adjustSize(); });
        });
        right->addWidget(editor); right->addStretch();
        auto *buttons = new QHBoxLayout; buttons->setSpacing(6);
        save = new QPushButton("Save"); start = new QPushButton("Connect"); start->setObjectName("primary");
        stop = new QPushButton("Disconnect"); stop->setObjectName("danger"); stop->setEnabled(false);
        buttons->addWidget(save); buttons->addWidget(start); buttons->addWidget(stop); right->addLayout(buttons);
        auto *logBar = new QHBoxLayout;
        auto *logToggle = new QToolButton; logToggle->setText("Log"); logToggle->setCheckable(true);
        logToggle->setToolButtonStyle(Qt::ToolButtonTextBesideIcon); logToggle->setArrowType(Qt::RightArrow);
        logBar->addWidget(logToggle); logBar->addStretch();
        auto *about = new QToolButton; about->setText("About"); logBar->addWidget(about);
        connect(about, &QToolButton::clicked, this, [this] {
            QMessageBox box(this); box.setWindowTitle("About VoidTunnel");
            box.setTextFormat(Qt::RichText);
            box.setText(QString("VoidTunnel 1.0<br>Built with Qt %1 (LGPLv3).<br><br>"
                        "<a href='https://github.com/justillhackyou/VoidTunnel'>Application source and build scripts</a><br>"
                        "<a href='https://download.qt.io/official_releases/qt/6.8/6.8.3/submodules/qtbase-everywhere-src-6.8.3.tar.xz'>Qt source code</a><br>"
                        "<a href='https://doc.qt.io/qt-6/licenses-used-in-qt.html'>Qt third-party notices</a><br><br>"
                        "You may rebuild and relink VoidTunnel with a modified Qt.").arg(qVersion()));
            QString text;
            for (const QString &path : {QString(":/licenses/LGPL-3.0-only.txt"), QString(":/licenses/GPL-3.0-only.txt")}) {
                QFile f(path); if (f.open(QIODevice::ReadOnly)) text += QString::fromUtf8(f.readAll()) + "\n\n";
            }
            box.setDetailedText(text); box.exec();
        });
        auto *clear = new QPushButton("Clear"); clear->hide(); logBar->addWidget(clear); outer->addLayout(logBar);
        logs = new QPlainTextEdit; logs->setReadOnly(true); logs->setMaximumBlockCount(2000);
        logs->setFixedHeight(120); logs->hide(); outer->addWidget(logs);
        connect(logToggle, &QToolButton::toggled, this, [this, logToggle, clear](bool expanded) {
            logs->setVisible(expanded); clear->setVisible(expanded);
            logToggle->setArrowType(expanded ? Qt::DownArrow : Qt::RightArrow);
            QTimer::singleShot(0, this, [this] { adjustSize(); });
        });
        setStyleSheet(R"(
            QWidget { background:#101119; color:#dce0ec; font-family:'Segoe UI',sans-serif; font-size:12px; }
            QLabel#brand { font-size:18px; font-weight:600; }
            QLabel#badge { color:#8e96ac; }
            QLineEdit,QSpinBox { background:#171a26; border:1px solid #34394c; padding:4px 6px; selection-background-color:#6348a5; }
            QLineEdit:focus,QSpinBox:focus { border-color:#a183ef; }
            QPushButton { background:#212535; border:1px solid #3b4258; padding:5px 9px; }
            QPushButton:hover { background:#2c3248; border-color:#8e77c4; }
            QPushButton:pressed { background:#37304f; }
            QPushButton#primary { background:#6543ad; border-color:#9270d6; color:white; }
            QPushButton#primary:hover { background:#7753bf; }
            QPushButton#danger { color:#ee8b9c; }
            QPushButton:disabled { color:#646a7d; background:#191c28; border-color:#292e3d; }
            QToolButton { border:0; color:#a5aabd; padding:3px 0; }
            QToolButton:hover { color:#c4aff2; }
            QListWidget { background:#151823; border:1px solid #30364a; outline:0; }
            QListWidget::item { padding:7px; }
            QListWidget::item:selected { background:#35284f; color:#e2d5fc; }
            QPlainTextEdit { background:#0c0e15; color:#a2b8cf; border:1px solid #30364a; font-family:'Consolas',monospace; font-size:11px; }
            QCheckBox { spacing:6px; }
            QScrollBar:vertical { background:#151823; width:8px; }
            QScrollBar::handle:vertical { background:#454058; min-height:20px; }
        )");
        connect(add, &QPushButton::clicked, this, &Window::newProfile);
        connect(del, &QPushButton::clicked, this, &Window::deleteProfile);
        connect(save, &QPushButton::clicked, this, [this] { saveProfile(); });
        connect(start, &QPushButton::clicked, this, [this] {
            if (!saveProfile()) return;
            setBusy(true); tunnel.start(profiles.at(nodes->currentRow()));
        });
        connect(stop, &QPushButton::clicked, &tunnel, &Tunnel::stop);
        connect(clear, &QPushButton::clicked, logs, &QPlainTextEdit::clear);
        connect(browse, &QPushButton::clicked, this, [this] {
            QString path = QFileDialog::getOpenFileName(this, "Select an OpenSSH private key");
            if (!path.isEmpty()) key->setText(QDir::toNativeSeparators(path));
        });
        connect(nodes, &QListWidget::currentRowChanged, this, &Window::loadEditor);
        connect(&tunnel, &Tunnel::log, this, &Window::appendLog);
        connect(&tunnel, &Tunnel::state, this, [this](const QString &text, bool online) {
            badge->setText(text);
            badge->setStyleSheet(QString("color:%1;")
                                .arg(online ? "#76d5b6" : "#a295c0"));
            if (!tunnel.active()) setBusy(false);
        });
        connect(&tunnel, &Tunnel::stopped, this, [this] { if (!tunnel.active()) setBusy(false); });
        loadProfiles();
        appendLog("Ready.");
        appendLog("Disconnect before editing the active profile.");
    }
protected:
    void closeEvent(QCloseEvent *event) override {
        if (tunnel.active()) tunnel.stop();
        event->accept();
    }
private:
    QListWidget *nodes;
    QLineEdit *name, *connection, *key, *secret, *bind, *localHost;
    QSpinBox *sshPort, *remotePort, *localPort;
    QCheckBox *remember;
    QPushButton *save, *start, *stop;
    QLabel *badge;
    QWidget *editor;
    QPlainTextEdit *logs;
    QVector<Profile> profiles;
    Tunnel tunnel;
    static QSpinBox *portSpin(int value) {
        auto *s = new QSpinBox; s->setRange(1, 65535); s->setValue(value); s->setButtonSymbols(QAbstractSpinBox::NoButtons); return s;
    }
    void appendLog(const QString &text) {
        logs->appendPlainText(QTime::currentTime().toString("HH:mm:ss") + "  " + text);
        logs->verticalScrollBar()->setValue(logs->verticalScrollBar()->maximum());
    }
    void setBusy(bool busy) {
        editor->setEnabled(!busy); nodes->setEnabled(!busy);
        save->setEnabled(!busy); start->setEnabled(!busy); stop->setEnabled(busy);
    }
    bool writeProfiles() {
        QJsonArray array;
        for (const auto &p : profiles) array.append(p.json());
        QSaveFile file(dataDirectory() + "/profiles.json");
        if (!file.open(QIODevice::WriteOnly)) { error(file.errorString()); return false; }
        file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
        QByteArray bytes = QJsonDocument(QJsonObject{{"version", 1}, {"profiles", array}}).toJson();
        if (file.write(bytes) != bytes.size() || !file.commit()) { error(file.errorString()); return false; }
        return true;
    }
    void error(const QString &s) { QMessageBox::warning(this, "VoidTunnel", s); }
    void loadProfiles() {
        QFile file(dataDirectory() + "/profiles.json");
        if (file.exists()) {
            if (!file.open(QIODevice::ReadOnly)) { error(file.errorString()); return; }
            QJsonParseError e;
            auto doc = QJsonDocument::fromJson(file.readAll(), &e);
            if (e.error != QJsonParseError::NoError || !doc.isObject() ||
                doc.object().value("version").toInt() != 1 || !doc.object().value("profiles").isArray()) {
                error("Could not read profiles.json. Back up the file before making changes.");
                start->setEnabled(false); save->setEnabled(false); nodes->setEnabled(false);
                storageBroken = true; return;
            }
            for (const auto &v : doc.object().value("profiles").toArray()) {
                if (!v.isObject()) continue;
                Profile p = Profile::fromJson(v.toObject());
                auto decoded = unprotect(p.protectedSecret);
                if (decoded) p.secret = *decoded;
                else appendLog("DPAPI: password for \"" + p.name + "\" is unavailable. Enter it again.");
                profiles.append(p); nodes->addItem(p.name);
            }
        }
        if (profiles.isEmpty()) newProfile(); else nodes->setCurrentRow(0);
    }
    bool storageBroken = false;
    void newProfile() {
        if (tunnel.active() || storageBroken) return;
        Profile p; p.name = "Server " + QString::number(profiles.size()+1);
        profiles.append(p); nodes->addItem(p.name); nodes->setCurrentRow(profiles.size()-1);
    }
    void deleteProfile() {
        if (tunnel.active() || storageBroken) return;
        int row = nodes->currentRow(); if (row < 0) return;
        if (QMessageBox::question(this, "Remove profile", "Remove \"" + profiles[row].name + "\"?") != QMessageBox::Yes) return;
        auto backup = profiles; profiles.removeAt(row);
        if (!writeProfiles()) { profiles = backup; return; }
        delete nodes->takeItem(row);
        if (profiles.isEmpty()) newProfile(); else loadEditor(nodes->currentRow());
    }
    void loadEditor(int row) {
        if (row < 0 || row >= profiles.size()) return;
        const Profile &p = profiles[row];
        name->setText(p.name); connection->setText(p.user.isEmpty() ? p.host : p.user + '@' + p.host);
        key->setText(p.key); secret->setText(p.secret); remember->setChecked(p.remember);
        sshPort->setValue(p.sshPort); remotePort->setValue(p.remotePort); localPort->setValue(p.localPort);
        bind->setText(p.bind); localHost->setText(p.localHost);
    }
    bool saveProfile() {
        int row = nodes->currentRow(); if (row < 0 || storageBroken) return false;
        Profile p = profiles[row]; p.name = name->text().trimmed();
        QString address = connection->text().trimmed(); int at = address.lastIndexOf('@');
        if (at <= 0 || at == address.size()-1) { error("Enter the server as user@host."); return false; }
        p.user = address.left(at); p.host = unbracket(address.mid(at+1));
        p.key = key->text().trimmed(); p.secret = secret->text(); p.remember = remember->isChecked();
        p.sshPort = sshPort->value(); p.remotePort = remotePort->value(); p.localPort = localPort->value();
        p.bind = unbracket(bind->text().trimmed()); p.localHost = unbracket(localHost->text().trimmed());
        QString issue = validate(p); if (!issue.isEmpty()) { error(issue); return false; }
        if (p.remember) {
            auto encrypted = protect(p.secret);
            if (!encrypted) { error("Could not encrypt the password. Uncheck Remember password or try again."); return false; }
            p.protectedSecret = *encrypted;
        } else p.protectedSecret.clear();
        Profile previous = profiles[row]; profiles[row] = p;
        if (!writeProfiles()) { profiles[row] = previous; return false; }
        nodes->item(row)->setText(p.name); appendLog("Profile \"" + p.name + "\" saved."); return true;
    }
};

int selfTest() {
    int failures = 0;
    auto check = [&failures](bool ok, const char *label) {
        fprintf(stdout, "%s %s\n", ok ? "PASS" : "FAIL", label); if (!ok) ++failures;
    };
    Profile p; p.name = "test"; p.host = "example.com"; p.user = "alice";
    check(validate(p).isEmpty(), "valid profile");
    p.host = "-oProxyCommand=bad"; check(!validate(p).isEmpty(), "reject option injection");
    p.host = "example.com"; p.localPort = 0; check(!validate(p).isEmpty(), "reject invalid port");
    p.localPort = 1111; p.secret = "secret";
    check(!QJsonDocument(p.json()).toJson().contains("\"secret\""), "no plaintext secret on disk");
    auto args = sshArguments(p, "C:/Users/Test User/known_hosts");
    check(args.contains("127.0.0.1:2222:127.0.0.1:1111"), "reverse mapping direction");
    check(args.contains("UserKnownHostsFile=\"C:/Users/Test User/known_hosts\""), "quote known_hosts with spaces");
    check(args.contains("StrictHostKeyChecking=accept-new"), "TOFU without accepting changed keys");
    check(args.contains("ServerAliveCountMax=3") && args.contains("ExitOnForwardFailure=yes"), "liveness and forwarding failure");
    check(forwardingHost("::1") == "[::1]", "IPv6 forwarding brackets");
    check(Profile::fromJson(p.json()).remotePort == 2222, "profile serialization");
#ifdef Q_OS_WIN
    auto encrypted = protect("test passphrase 123");
    check(encrypted && unprotect(*encrypted) == std::optional<QString>("test passphrase 123"), "DPAPI roundtrip");
#endif
    // Exercise the actual helper process, authentication token and IPC framing.
    for (bool authorized : {true, false}) {
        QLocalServer ipc;
        ipc.setSocketOptions(QLocalServer::UserAccessOption);
        QString pipe = "VoidTunnel-test-" + freshId();
        bool listening = ipc.listen(pipe);
        QObject::connect(&ipc, &QLocalServer::newConnection, &ipc, [&ipc] {
            auto *socket = ipc.nextPendingConnection();
            auto request = std::make_shared<QByteArray>();
            QObject::connect(socket, &QLocalSocket::readyRead, socket, [socket, request] {
                *request += socket->readAll();
                if (!request->contains('\n')) return;
                bool ok = request->trimmed() == "test-token";
                QJsonObject o{{"ok", ok}};
                if (ok) o.insert("secret", "test-secret");
                socket->write(QJsonDocument(o).toJson(QJsonDocument::Compact) + '\n');
                socket->disconnectFromServer();
            });
            QObject::connect(socket, &QLocalSocket::disconnected, socket, &QObject::deleteLater);
        });
        QProcess helper;
        auto env = QProcessEnvironment::systemEnvironment();
        env.insert("VOIDTUNNEL_ASKPASS", "1"); env.insert("VOIDTUNNEL_PIPE", pipe);
        env.insert("VOIDTUNNEL_TOKEN", authorized ? "test-token" : "wrong-token");
        helper.setProcessEnvironment(env);
        QEventLoop loop; QTimer deadline; deadline.setSingleShot(true);
        QObject::connect(&deadline, &QTimer::timeout, &loop, &QEventLoop::quit);
        QObject::connect(&helper, qOverload<int, QProcess::ExitStatus>(&QProcess::finished),
                         &loop, &QEventLoop::quit);
        helper.start(QCoreApplication::applicationFilePath(), {"Password:"});
        deadline.start(8000); loop.exec();
        bool finished = helper.state() == QProcess::NotRunning;
        QByteArray result = helper.readAllStandardOutput();
        check(listening && finished && (authorized ? helper.exitCode() == 0 && result == "test-secret\n"
                                                  : helper.exitCode() != 0 && result.isEmpty()),
              authorized ? "askpass IPC secret delivery" : "askpass rejects invalid token");
        helper.kill(); helper.waitForFinished(1000);
    }
#ifndef Q_OS_WIN
    // Deterministic OpenSSH stand-in: verify askpass, fail once, then stay alive.
    // It tests our process lifecycle; it does not claim to test the SSH protocol.
    QTemporaryDir directory;
    QFile fake(directory.filePath("ssh"));
    bool setup = fake.open(QIODevice::WriteOnly);
    if (setup) {
        fake.write(R"SH(#!/bin/sh
answer=$("$SSH_ASKPASS" 'Password:') || exit 91
[ "$answer" = 'integration-secret' ] || exit 92
if [ ! -f "$VOIDTUNNEL_TEST_COUNTER" ]; then
    touch "$VOIDTUNNEL_TEST_COUNTER"
    exit 7
fi
printf 'debug1: remote forward success for: listen 127.0.0.1:2222\n' >&2
exec /bin/sleep 30
)SH");
        fake.close(); fake.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
    }
    QByteArray oldPath = qgetenv("PATH");
    qputenv("PATH", directory.path().toUtf8() + ':' + oldPath);
    qputenv("VOIDTUNNEL_TEST_COUNTER", directory.filePath("counter").toUtf8());
    {
        Tunnel testTunnel; QEventLoop loop; QTimer deadline; deadline.setSingleShot(true);
        bool ready = false, retrySeen = false;
        QObject::connect(&deadline, &QTimer::timeout, &loop, &QEventLoop::quit);
        QObject::connect(&testTunnel, &Tunnel::state, &loop, [&](const QString &text, bool online) {
            if (text.startsWith("Retry")) retrySeen = true;
            if (online) { ready = true; loop.quit(); }
        });
        p.secret = "integration-secret"; deadline.start(10000); testTunnel.start(p); loop.exec();
        check(setup && ready && retrySeen, "reconnect after SSH exit and authenticate again");
        testTunnel.stop();
        QEventLoop shutdown; QTimer::singleShot(200, &shutdown, &QEventLoop::quit); shutdown.exec();
        check(!testTunnel.active(), "stop disables reconnect and closes child process");
    }
    qputenv("PATH", oldPath); qunsetenv("VOIDTUNNEL_TEST_COUNTER");
#endif
    return failures == 0 ? 0 : 1;
}

int main(int argc, char **argv) {
    if (qEnvironmentVariable("VOIDTUNNEL_ASKPASS") == "1") {
        QCoreApplication app(argc, argv); return askpass();
    }
    QApplication app(argc, argv);
    QCoreApplication::setOrganizationName("VoidTunnel");
    QCoreApplication::setApplicationName("VoidTunnel");
    QCoreApplication::setApplicationVersion("1.0.0");
    if (app.arguments().contains("--self-test")) return selfTest();
    if (!QDir().mkpath(dataDirectory())) {
        QMessageBox::critical(nullptr, "VoidTunnel", "Could not create data directory: " + dataDirectory()); return 1;
    }
    QLockFile lock(dataDirectory() + "/instance.lock");
    if (!lock.tryLock(0)) {
        QMessageBox::information(nullptr, "VoidTunnel", "VoidTunnel is already running or its data directory is locked."); return 1;
    }
    Window window; window.show(); return app.exec();
}
#include "main.moc"
