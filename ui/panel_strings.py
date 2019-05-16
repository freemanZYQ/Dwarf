"""
Dwarf - Copyright (C) 2019 Giovanni Rocca (iGio90)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>
"""
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import QWidget, QLineEdit, QVBoxLayout, QHBoxLayout, QRadioButton, QPushButton, QProgressDialog, \
    QSizePolicy, QApplication

from ui.list_view import DwarfListView
from lib import utils
from ui.hex_edit import HighLight, HighlightExistsError


class StringsThread(QThread):
    onCmdCompleted = pyqtSignal(str, name='onCmdCompleted')
    onError = pyqtSignal(str, name='onError')

    dwarf = None
    start = 0
    size = 0
    module = None

    def __init__(self, dwarf=None, parent=None):
        super().__init__(parent=parent)
        self.dwarf = dwarf

    def run(self):
        if self.dwarf is None:
            self.onError.emit('Dwarf missing')
            return
        if self.pattern is '' or len(self.pattern) <= 0:
            self.onError.emit('Pattern missing')
            return
        if len(self.ranges) <= 0:
            self.onError.emit('Ranges missing')
            return

        _strings = []
        if self.module is not None:
            _strings = self.dwarf.dwarf_api('enumerateStringsModule', self.module)
        elif self.start > 0:
            _strings = self.dwarf.dwarf_api('enumerateStrings', [self.start, self.size])

        self.onCmdCompleted.emit(_strings)


class StringsPanel(QWidget):
    """ SearchPanel
    """

    def __init__(self, parent=None):
        super(StringsPanel, self).__init__(parent=parent)
        self._app_window = parent

        if self._app_window.dwarf is None:
            print('StringsPanel created before Dwarf exists')
            return

        self._model = QStandardItemModel(0, 2)

        # just replicate ranges panel model
        self._model.setHeaderData(0, Qt.Horizontal, 'String')
        self._model.setHeaderData(0, Qt.Horizontal, Qt.AlignCenter, Qt.TextAlignmentRole)
        self._model.setHeaderData(1, Qt.Horizontal, 'Address')
        self._model.setHeaderData(1, Qt.Horizontal, Qt.AlignCenter, Qt.TextAlignmentRole)

        self.progress = None

        self.results = DwarfListView(self)
        self.results.setModel(self._model)

        box = QVBoxLayout()
        box.addWidget(self.results)
        self.setLayout(box)

    # ************************************************************************
    # **************************** Functions *********************************
    # ************************************************************************

    # ************************************************************************
    # **************************** Handlers **********************************
    # ************************************************************************
    def _on_dblclicked(self, model_index):
        item = self._result_model.itemFromIndex(model_index)
        if item:
            self.onShowMemoryRequest.emit(
                self._result_model.item(model_index.row(), 0).text())
