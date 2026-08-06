"""
Dynamic form generator mapping ModuleOption definitions to PyQt input forms.
"""

from typing import List, Dict, Any
from PyQt6.QtWidgets import QWidget, QFormLayout, QLineEdit, QSpinBox, QCheckBox, QComboBox
from core.base_module import ModuleOption, OptionType


class ConfigFormGenerator(QWidget):

    def __init__(self, options: List[ModuleOption]):
        super().__init__()
        self.layout = QFormLayout(self)
        self.fields: Dict[str, QWidget] = {}

        for opt in options:
            if opt.option_type == OptionType.STRING or opt.option_type == OptionType.FILE_PATH:
                field = QLineEdit()
                if opt.default:
                    field.setText(str(opt.default))
            elif opt.option_type == OptionType.INTEGER:
                field = QSpinBox()
                field.setMaximum(65535)
                if opt.default is not None:
                    field.setValue(int(opt.default))
            elif opt.option_type == OptionType.BOOLEAN:
                field = QCheckBox()
                if opt.default:
                    field.setChecked(bool(opt.default))
            elif opt.option_type == OptionType.ENUM:
                field = QComboBox()
                if opt.choices:
                    field.addItems(opt.choices)
            else:
                field = QLineEdit()

            self.layout.addRow(opt.name, field)
            self.fields[opt.name] = field
