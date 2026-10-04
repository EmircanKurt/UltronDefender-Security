using System.Windows.Controls;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
using System.Windows.Automation.Provider;

namespace AegisPC.App.Controls;

/// <summary>A command-driven checkbox whose indicator changes only with its observed-state binding, never optimistically on click.</summary>
public sealed class ObservedProtectionSwitch : CheckBox
{
    /// <summary>Suppresses local visual toggling; ButtonBase still executes the command for mouse and Space activation.</summary>
    protected override void OnToggle() { }

    /// <summary>Routes assistive-technology Toggle requests through the same consent command without changing the observed indicator.</summary>
    protected override AutomationPeer OnCreateAutomationPeer() => new ObservedProtectionSwitchAutomationPeer(this);

    private sealed class ObservedProtectionSwitchAutomationPeer(ObservedProtectionSwitch owner)
        : ToggleButtonAutomationPeer(owner), IToggleProvider
    {
        public override object GetPattern(PatternInterface patternInterface) =>
            patternInterface == PatternInterface.Toggle ? this : base.GetPattern(patternInterface);

        ToggleState IToggleProvider.ToggleState => owner.IsChecked switch
        {
            true => ToggleState.On,
            false => ToggleState.Off,
            _ => ToggleState.Indeterminate
        };

        void IToggleProvider.Toggle()
        {
            if (!owner.IsEnabled) throw new ElementNotEnabledException();
            var command = owner.Command;
            if (command?.CanExecute(owner.CommandParameter) == true) command.Execute(owner.CommandParameter);
        }
    }
}
