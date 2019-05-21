import os
import random
import json

from PyQt5.QtCore import Qt, QSize, QRect, pyqtSignal, QThread, QMargins
from PyQt5.QtGui import QFont, QPixmap, QIcon, QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import QWidget, QListWidget, QListWidgetItem, QDialog, QLabel, QVBoxLayout, QHBoxLayout, \
    QPushButton, QListView, QSpacerItem, QSizePolicy, QStyle, qApp, QHeaderView

from lib import utils, prefs
from lib.git import Git
from ui.list_view import DwarfListView


class DwarfCommitsThread(QThread):
    """ Commits Thread
    signals:
            on_status_text(str)
            on_add_commit(str, bool) - adds item to list (bool == use white color)
            on_update_available()
            on_finished(str)
    """

    on_status_text = pyqtSignal(str)
    on_update_available = pyqtSignal()
    on_add_commit = pyqtSignal(str, bool)
    on_finished = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)

    def run(self):
        self.on_status_text.emit('fetching commit list...')

        try:
            utils.do_shell_command('git --version')
        except IOError as io_error:
            if io_error.errno == 2:
                # git command not available
                self.on_status_text.emit('error: git not available on your system')
                return
        _git = Git()
        data = _git.get_dwarf_commits()
        if data is None:
            self.on_status_text.emit('Failed to fetch commit list. Try later.')
            return

        most_recent_remote_commit = ''
        most_recent_local_commit = utils.do_shell_command('git log -1 master --pretty=format:%H')
        most_recent_date = ''
        for commit in data:
            if most_recent_remote_commit == '':
                most_recent_remote_commit = commit['sha']
                if most_recent_remote_commit != most_recent_local_commit:
                    self.on_update_available.emit()

            commit = commit['commit']
            date = commit['committer']['date'].split('T')
            if most_recent_date != date[0]:
                if most_recent_date != '':
                    self.on_add_commit.emit('', True)
                self.on_add_commit.emit(date[0], True)
                most_recent_date = date[0]

            s = ('{0} - {1} ({2})'.format(date[1][:-1], commit['message'], commit['author']['name']))
            self.on_add_commit.emit(s, False)

        if most_recent_remote_commit != most_recent_local_commit:
            self.on_finished.emit('There is an newer Version available... You can use the UpdateButton in Menu')
        else:
            # keep: it clears status text
            self.on_finished.emit('')


class DwarfUpdateThread(QThread):
    """ Dwarf update Thread
        signals:
            on_status_text(str)
            on_finished(str)
    """

    on_status_text = pyqtSignal(str)
    on_finished = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)

    def run(self):
        self.on_status_text.emit('updating dwarf...')

        try:
            utils.do_shell_command('git --version')
        except IOError as io_error:
            if io_error.errno == 2:
                # git command not available
                self.on_status_text.emit('error while updating: git not available on your system')
                self.on_finished.emit('error while updating: git not available on your system')
                return

        utils.do_shell_command('git fetch -q https://github.com/iGio90/Dwarf.git')
        utils.do_shell_command('git checkout -f -q master')
        utils.do_shell_command('git reset --hard FETCH_HEAD')
        sha = utils.do_shell_command('git log -1 master --pretty=format:%H')

        s = ('Dwarf updated to commit := {0} - Please restart...'.format(sha))
        self.on_status_text.emit(s)
        self.on_finished.emit(sha)


class UpdateBar(QWidget):
    onUpdateNowClicked = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.setAutoFillBackground(True)
        self.setStyleSheet('background-color: crimson; color: white; font-weight: bold; margin: 0; padding: 10px;')
        self.setup()

    def setup(self):
        """ Setup ui
        """
        h_box = QHBoxLayout()
        h_box.setContentsMargins(0, 0, 0, 0)
        update_label = QLabel('A newer Version of Dwarf is available. Checkout <a style="color:white;" '
                              'href="https://github.com/iGio90/Dwarf">Dwarf on GitHub</a> for more informations')
        update_label.setOpenExternalLinks(True)
        update_label.setTextFormat(Qt.RichText)
        update_label.setFixedHeight(35)
        update_label.setTextInteractionFlags(Qt.TextBrowserInteraction)

        update_button = QPushButton('Update now!', update_label)
        update_button.setStyleSheet('padding: 0; border-color: white;')
        update_button.setGeometry(update_label.width() + 50, 5, 100, 25)
        update_button.clicked.connect(self.update_now_clicked)
        h_box.addWidget(update_label)
        self.setLayout(h_box)

    def update_now_clicked(self):
        """ Update Button clicked
        """
        self.onUpdateNowClicked.emit()


class WelcomeDialog(QDialog):
    onSessionSelected = pyqtSignal(str, name='onSessionSelected')
    onUpdateComplete = pyqtSignal(name='onUpdateComplete')
    onIsNewerVersion = pyqtSignal(name='onIsNewerVersion')

    def __init__(self, parent=None):
        super(WelcomeDialog, self).__init__(parent=parent)

        self._prefs = parent.prefs

        self._sub_titles = [
            ['duck', 'dumb', 'doctor', 'dutch', 'dark', 'dirty'],
            ['warriors', 'wardrobes', 'waffles', 'wishes'],
            ['are', 'aren\'t', 'ain\'t', 'appears to be'],
            ['rich', 'real', 'riffle', 'retarded', 'rock'],
            ['as fuck', 'fancy', 'fucked', 'front-ended', 'falafel', 'french fries'],
        ]

        self._recent_list_model = QStandardItemModel(0, 7)
        self._recent_list_model.setHeaderData(0, Qt.Horizontal, 'Path')
        self._recent_list_model.setHeaderData(1, Qt.Horizontal, 'Session')
        self._recent_list_model.setHeaderData(1, Qt.Horizontal, Qt.AlignCenter, Qt.TextAlignmentRole)
        self._recent_list_model.setHeaderData(2, Qt.Horizontal, 'Hooks')
        self._recent_list_model.setHeaderData(2, Qt.Horizontal, Qt.AlignCenter, Qt.TextAlignmentRole)
        self._recent_list_model.setHeaderData(3, Qt.Horizontal, 'Watchers')
        self._recent_list_model.setHeaderData(3, Qt.Horizontal, Qt.AlignCenter, Qt.TextAlignmentRole)
        self._recent_list_model.setHeaderData(4, Qt.Horizontal, 'OnLoads')
        self._recent_list_model.setHeaderData(4, Qt.Horizontal, Qt.AlignCenter, Qt.TextAlignmentRole)
        self._recent_list_model.setHeaderData(5, Qt.Horizontal, 'Bookmarks')
        self._recent_list_model.setHeaderData(5, Qt.Horizontal, Qt.AlignCenter, Qt.TextAlignmentRole)
        self._recent_list_model.setHeaderData(6, Qt.Horizontal, 'Custom script')
        self._recent_list_model.setHeaderData(6, Qt.Horizontal, Qt.AlignCenter, Qt.TextAlignmentRole)

        self._recent_list = DwarfListView()
        self._recent_list.setModel(self._recent_list_model)

        self._recent_list.header().setSectionResizeMode(0, QHeaderView.ResizeToContents | QHeaderView.Interactive)
        self._recent_list.header().setSectionResizeMode(1, QHeaderView.Stretch)
        self._recent_list.header().setSectionResizeMode(2, QHeaderView.Stretch)
        self._recent_list.header().setSectionResizeMode(3, QHeaderView.Stretch)
        self._recent_list.header().setSectionResizeMode(4, QHeaderView.Stretch)
        self._recent_list.header().setSectionResizeMode(5, QHeaderView.Stretch)
        self._recent_list.header().setSectionResizeMode(6, QHeaderView.Stretch)

        self._recent_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self._recent_list.customContextMenuRequested.connect(self._on_recent_sessions_context_menu)

        _section_width = self._recent_list.header().sectionSize(2)
        self._new_pixmap = QPixmap(_section_width, 20)
        self._new_pixmap.fill(Qt.transparent)
        self._dot_icon = QIcon(self._new_pixmap)

        # setup size and remove/disable titlebuttons
        self.setFixedSize(800, 400)
        self.setSizeGripEnabled(False)
        self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.setWindowFlag(Qt.WindowContextHelpButtonHint, False)
        self.setWindowFlag(Qt.WindowCloseButtonHint, True)
        self.setModal(True)

        # setup ui elements
        self.setup_ui()

        self.update_commits_thread = DwarfCommitsThread(parent)
        self.update_commits_thread.on_update_available.connect(self._on_dwarf_isupdate)
        self.update_commits_thread.start()
        # center
        self.setGeometry(
            QStyle.alignedRect(Qt.LeftToRight, Qt.AlignCenter, self.size(), qApp.desktop().availableGeometry()))

    def setup_ui(self):
        """ Setup Ui
        """
        main_wrap = QVBoxLayout()
        main_wrap.setContentsMargins(0, 0, 0, 0)

        # updatebar on top
        self.update_bar = UpdateBar(self)
        self.update_bar.onUpdateNowClicked.connect(self._update_dwarf)
        self.update_bar.setVisible(False)
        main_wrap.addWidget(self.update_bar)

        # main content
        h_box = QHBoxLayout()
        h_box.setContentsMargins(15, 15, 15, 15)
        wrapper = QVBoxLayout()
        # wrapper.setGeometry(QRect(0, 0, 400, 200))
        head = QHBoxLayout()
        head.setContentsMargins(0, 20, 0, 20)
        # dwarf icon
        icon = QLabel()
        icon.setContentsMargins(40, 0, 0, 0)
        dwarf_logo = QPixmap(utils.resource_path('assets/dwarf.png'))
        icon.setPixmap(dwarf_logo)
        head.addWidget(icon)

        # main title
        v_box = QVBoxLayout()
        title = QLabel('Dwarf')
        title.setContentsMargins(0, 0, 50, 0)
        title.setFont(QFont('Anton', 90, QFont.Bold))
        title.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        title.setFixedHeight(110)
        title.setAlignment(Qt.AlignCenter)
        v_box.addWidget(title)

        sub_title_text = (self._pick_random_word(0) + ' ' + self._pick_random_word(1) + ' ' +
                          self._pick_random_word(2) + ' ' + self._pick_random_word(3) + ' ' +
                          self._pick_random_word(4))
        sub_title_text = sub_title_text[:1].upper() + sub_title_text[1:]
        sub_title = QLabel(sub_title_text)
        sub_title.setFont(QFont('OpenSans', 14, QFont.Bold))
        sub_title.setFixedHeight(25)
        sub_title.setAlignment(Qt.AlignCenter)
        sub_title.setContentsMargins(0, 0, 50, 0)
        sub_title.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        v_box.addWidget(sub_title)
        head.addLayout(v_box)

        wrapper.addLayout(head)

        recent = QLabel('Last saved Sessions')
        font = recent.font()
        font.setBold(True)
        font.setPointSize(10)
        recent.setFont(font)
        wrapper.addWidget(recent)
        wrapper.addWidget(self._recent_list)
        h_box.addLayout(wrapper, stretch=False)
        buttonSpacer = QSpacerItem(15, 100, QSizePolicy.Fixed, QSizePolicy.Minimum)
        h_box.addItem(buttonSpacer)
        wrapper = QVBoxLayout()

        btn = QPushButton()
        ico = QIcon(QPixmap(utils.resource_path('assets/android.png')))
        btn.setIconSize(QSize(75, 75))
        btn.setIcon(ico)
        btn.setToolTip('New Android Session')
        btn.clicked.connect(self._on_android_button)

        wrapper.addWidget(btn)
        btn = QPushButton()
        ico = QIcon(QPixmap(utils.resource_path('assets/apple.png')))
        btn.setIconSize(QSize(75, 75))
        btn.setIcon(ico)
        btn.setToolTip('New iOS Session')
        wrapper.addWidget(btn)

        btn = QPushButton()
        ico = QIcon(QPixmap(utils.resource_path('assets/local.png')))
        btn.setIconSize(QSize(75, 75))
        btn.setIcon(ico)
        btn.setToolTip('New Local Session')
        btn.clicked.connect(self._on_local_button)
        wrapper.addWidget(btn)

        btn = QPushButton()
        ico = QIcon(QPixmap(utils.resource_path('assets/remote.png')))
        btn.setIconSize(QSize(75, 75))
        btn.setIcon(ico)
        btn.setToolTip('New Remote Session')
        btn.clicked.connect(self._on_remote_button)
        wrapper.addWidget(btn)

        session_history = self._prefs.get(prefs.RECENT_SESSIONS, default=[])
        invalid_session_files = []
        for recent_session_file in session_history:
            if os.path.exists(recent_session_file):
                with open(recent_session_file, 'r') as f:
                    exported_session = json.load(f)
                hooks = '0'
                watchers = '0'
                onLoads = '0'
                bookmarks = '0'
                have_user_script = False
                if 'hooks' in exported_session and exported_session['hooks'] is not None:
                    hooks = str(len(exported_session['hooks']))
                if 'watchers' in exported_session and exported_session['watchers'] is not None:
                    watchers = str(len(exported_session['watchers']))
                if 'onLoads' in exported_session and exported_session['onLoads'] is not None:
                    onLoads = str(len(exported_session['onLoads']))
                if 'bookmarks' in exported_session and exported_session['bookmarks'] is not None:
                    bookmarks = str(len(exported_session['bookmarks']))
                if 'user_script' in exported_session and exported_session['user_script']:
                    have_user_script = exported_session['user_script'] != ''

                user_script_item = QStandardItem()
                if have_user_script:
                    user_script_item.setIcon(self._dot_icon)

                self._recent_list_model.insertRow(self._recent_list_model.rowCount(), [
                    QStandardItem(recent_session_file),
                    QStandardItem(exported_session['session']),
                    QStandardItem(hooks),
                    QStandardItem(watchers),
                    QStandardItem(onLoads),
                    QStandardItem(bookmarks),
                    QStandardItem(user_script_item),
                ])
            else:
                invalid_session_files.append(recent_session_file)
        for invalid in invalid_session_files:
            session_history.pop(session_history.index(invalid))
        self._prefs.put(prefs.RECENT_SESSIONS, session_history)

        h_box.addLayout(wrapper, stretch=False)
        main_wrap.addLayout(h_box)
        self.setLayout(main_wrap)

    def _on_dwarf_isupdate(self):
        self.update_bar.setVisible(True)
        self.onIsNewerVersion.emit()

    def _update_dwarf(self):
        self._update_thread = DwarfUpdateThread(self)
        self._update_thread.on_finished.connect(self._update_finished)
        if not self._update_thread.isRunning():
            self._update_thread.start()

    def _update_finished(self):
        self.onUpdateComplete.emit()

    def _on_android_button(self):
        self.onSessionSelected.emit('Android')
        self.close()

    def _on_local_button(self):
        self.onSessionSelected.emit('Local')
        self.close()

    def _on_remote_button(self):
        self.onSessionSelected.emit('Remote')
        self.close()

    def _pick_random_word(self, arr):
        return self._sub_titles[arr][random.randint(0, len(self._sub_titles[arr]) - 1)]

    def _on_recent_sessions_context_menu(self):
        pass
