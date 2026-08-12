
#Dynamic form generator mapping ModuleOption definitions to PyQt input forms.


from typing import Any, Dict, List

from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QLineEdit,
    QSpinBox,
    QWidget,
)

from core.base_module import ModuleOption, OptionType


class ConfigFormGenerator(QWidget):
   # Generate a PyQt configuration form from ModuleOption definitions.

    def __init__(self, options: List[ModuleOption]) -> None:
        super().__init__()

        self.form_layout = QFormLayout(self)
        self.fields: Dict[str, QWidget] = {}

        for option in options:
            field = self._create_field(option)

            if option.description:
                field.setToolTip(option.description)

            self.form_layout.addRow(option.name, field)
            self.fields[option.name] = field

    def _create_field(self, option: ModuleOption) -> QWidget:
       # Create the appropriate Qt input widget for an option
        if option.option_type in (
            OptionType.STRING,
            OptionType.FILE_PATH,
        ):
            field = QLineEdit()

            if option.default is not None:
                field.setText(str(option.default))

            return field

        if option.option_type == OptionType.INTEGER:
            field = QSpinBox()
            field.setMaximum(65535)

            if option.default is not None:
                field.setValue(int(option.default))

            return field

        if option.option_type == OptionType.BOOLEAN:
            field = QCheckBox()

            if option.default is not None:
                field.setChecked(bool(option.default))

            return field

        if option.option_type == OptionType.ENUM:
            field = QComboBox()

            if option.choices:
                field.addItems(option.choices)

            if option.default is not None:
                index = field.findText(str(option.default))
                if index >= 0:
                    field.setCurrentIndex(index)

            return field

        # Defensive fallback for a future OptionType.
        return QLineEdit()

    def get_values(self) -> Dict[str, Any]:
       # Return the current form values keyed by ModuleOption.name
        values: Dict[str, Any] = {}

        for name, field in self.fields.items():
            if isinstance(field, QLineEdit):
                values[name] = field.text()

            elif isinstance(field, QSpinBox):
                values[name] = field.value()

            elif isinstance(field, QCheckBox):
                values[name] = field.isChecked()

            elif isinstance(field, QComboBox):
                values[name] = field.currentText()

        return values

    def clear(self) -> None:
       # Reset all fields to their default/empty state
        for field in self.fields.values():
            if isinstance(field, QLineEdit):
                field.clear()

            elif isinstance(field, QSpinBox):
                field.setValue(0)

            elif isinstance(field, QCheckBox):
                field.setChecked(False)

            elif isinstance(field, QComboBox):
                field.setCurrentIndex(0)

